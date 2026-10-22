"""
Chakravyuh broker — the single policy-enforcing bridge between the sealed lanes.

This is the heart of the arena. Red, blue and model lanes run in separate
rootless containers on separate internal networks and CANNOT reach each other at
the network layer (enforced by Docker internal networks + nftables default-deny,
see docker/). The ONLY path between them is this broker, which:

  * issues least-privilege capability tokens per lane/phase (tokens.py)
  * evaluates every request against a default-deny policy (policy/engine.py)
  * enforces commit-reveal for red payloads (commit_reveal.py)
  * starts a FRESH model session per test (no cross-test contamination)
  * routes attack -> model -> blue-guard -> verdict, revealing to blue only the
    single in-flight prompt, never red's corpus
  * pads every response to a fixed latency quantum (padding.py)
  * writes a tamper-evident, signed audit record of everything (audit.py)
  * exposes ONLY metadata to the dashboard (no payload content)

Maps to objectives 01-06 and verticals 1-7; see docs/OBJECTIVES.md.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from common.audit import AuditLog
from common.commit_reveal import Commitment, verify_reveal
from .padding import LatencyPadder
from .policy.engine import PolicyEngine
from .tokens import TokenIssuer

# ---- configuration (overridable by env for container deployment) ----------- #
POLICY_PATH = os.environ.get("POLICY_PATH", os.path.join(os.path.dirname(__file__), "policy", "policy.yaml"))
AUDIT_DB = os.environ.get("AUDIT_DB", "/data/audit.db")
MODEL_URL = os.environ.get("MODEL_URL", "http://model:9000")
BLUE_URL = os.environ.get("BLUE_URL", "http://blue:9100")
QUANTUM_MS = float(os.environ.get("LATENCY_QUANTUM_MS", "50"))
BROKER_SECRET = os.environ.get("BROKER_SECRET", "dev-broker-secret-change-me").encode()

# Capabilities granted to each lane. Least privilege: red can never score,
# blue can never attack, model lane is passive.
LANE_CAPS = {
    "red": ["red.commit", "red.attack", "red.reveal"],
    "blue": ["blue.verdict"],
    "operator": ["operator.control"],
    "prober": ["canary.report"],   # may only submit a canary leakage report
}

# Per-subject bootstrap keys. A caller may mint a token for subject X only if it
# presents BOOTSTRAP_KEYS[X]. Each container is given ONLY its own key, so the
# untrusted red tenant cannot obtain an operator or blue token. Overridable via
# the BOOTSTRAP_KEYS env (JSON); the defaults are for local/dev use only.
BOOTSTRAP_KEYS = json.loads(os.environ.get("BOOTSTRAP_KEYS", json.dumps({
    "red": "dev-red-bootstrap-change-me",
    "blue": "dev-blue-bootstrap-change-me",
    "operator": "dev-operator-bootstrap-change-me",
    "prober": "dev-prober-bootstrap-change-me",
})))


class ArenaState:
    """In-memory state for the current test. Reset per test = fresh session."""

    def __init__(self):
        self.phase = "idle"            # idle -> commit -> running -> closed
        self.test_id: str | None = None
        self.commitment: Commitment | None = None
        self.model_session: str | None = None
        self.results: list[dict] = []   # metadata per attack (no payload content)
        self.verdicts = {"blocked": 0, "allowed": 0}
        self.canary_report: dict | None = None

    def snapshot(self) -> dict:
        return {
            "phase": self.phase,
            "test_id": self.test_id,
            "model_session": self.model_session,
            "committed": self.commitment.commitment[:16] + "…" if self.commitment else None,
            "n_committed_payloads": self.commitment.n_payloads if self.commitment else 0,
            "payloads_revealed": self.commitment.revealed if self.commitment else False,
            "attacks_processed": len(self.results),
            "verdicts": self.verdicts,
            "canary_report": self.canary_report,
        }


state = ArenaState()
issuer = TokenIssuer(BROKER_SECRET)
padder = LatencyPadder(QUANTUM_MS)
policy = PolicyEngine.from_file(POLICY_PATH)
audit: AuditLog
events: list[dict] = []   # metadata-only event feed for the dashboard


def feed(kind: str, **meta):
    events.append({"ts": time.time(), "kind": kind, **meta})
    if len(events) > 500:
        del events[:-500]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global audit
    audit = AuditLog(AUDIT_DB)
    audit.append("broker", "startup", {"quantum_ms": QUANTUM_MS, "policy": POLICY_PATH})
    feed("startup", quantum_ms=QUANTUM_MS)
    yield


app = FastAPI(title="Chakravyuh Broker", lifespan=lifespan)


def _auth(token: str | None, subject: str, action: str, target: str) -> list[str]:
    """Verify token, enforce default-deny policy; return capabilities or 403."""
    body = issuer.verify(token or "")
    if not body or body.get("sub") != subject:
        audit.append(subject, "auth_fail", {"action": action, "target": target})
        feed("policy_deny", subject=subject, action=action, target=target, reason="bad token")
        raise HTTPException(401, "invalid or missing capability token")
    caps = body.get("cap", [])
    decision = policy.evaluate(subject, action, target, state.phase, caps)
    audit.append(subject, "policy_decision",
                 {"action": action, "target": target, "phase": state.phase,
                  "allow": decision.allow, "rule": decision.rule})
    if not decision.allow:
        feed("policy_deny", subject=subject, action=action, target=target, reason=decision.reason)
        raise HTTPException(403, decision.reason)
    return caps


# --------------------------------------------------------------------------- #
# Token minting — gated by a per-subject BOOTSTRAP KEY.
#
# Previously this endpoint handed out any capability (including operator.control)
# to anyone. Now a caller must present the bootstrap key for the subject it is
# asking for, via the `X-Bootstrap` header. Each container is given ONLY its own
# key (see docker-compose.yml): the red tenant holds the red key and literally
# cannot obtain an operator or blue token, because it does not possess those
# keys and the broker — not the caller — holds the key→capability mapping.
#
# In production these per-lane keys would be short-lived identity documents
# minted by the orchestrator (or mTLS client certs); the env-injected keys here
# are the self-contained PoC equivalent and are overridable via BOOTSTRAP_KEYS.
# --------------------------------------------------------------------------- #
@app.get("/token/{subject}")
async def get_token(subject: str, x_bootstrap: str | None = Header(default=None)):
    if subject not in LANE_CAPS:
        raise HTTPException(404, "unknown subject")
    expected = BOOTSTRAP_KEYS.get(subject)
    if not expected or not x_bootstrap or not hmac.compare_digest(x_bootstrap, expected):
        audit.append("broker", "token_denied", {"subject": subject})
        feed("token_denied", subject=subject)
        raise HTTPException(401, "missing or invalid bootstrap key for this subject")
    audit.append("broker", "token_issued", {"subject": subject})
    return {"token": issuer.issue(subject, LANE_CAPS[subject])}


# --------------------------------------------------------------------------- #
# Operator controls
# --------------------------------------------------------------------------- #
@app.post("/test/open")
async def open_test(x_token: str | None = Header(default=None)):
    _auth(x_token, "operator", "open_test", "broker")
    state.__init__()  # fresh state => fresh model session, no contamination
    state.phase = "commit"
    state.test_id = uuid.uuid4().hex[:12]
    state.model_session = uuid.uuid4().hex[:12]
    audit.append("operator", "open_test",
                 {"test_id": state.test_id, "model_session": state.model_session})
    feed("open_test", test_id=state.test_id, model_session=state.model_session)
    return {"test_id": state.test_id, "phase": state.phase}


@app.post("/commit")
async def commit(payload: dict, x_token: str | None = Header(default=None)):
    """Red submits ONLY a commitment hash + payload count. No payload content."""
    _auth(x_token, "red", "commit", "broker")
    if state.phase != "commit":
        raise HTTPException(409, "not in commit phase")
    state.commitment = Commitment(
        test_id=state.test_id, commitment=payload["commitment"],
        n_payloads=int(payload["n_payloads"]))
    state.phase = "running"
    audit.append("red", "commit",
                 {"test_id": state.test_id, "commitment": payload["commitment"],
                  "n_payloads": state.commitment.n_payloads})
    feed("commit", n_payloads=state.commitment.n_payloads)
    return {"phase": state.phase, "commitment_recorded": True}


@app.post("/attack")
async def attack(payload: dict, x_token: str | None = Header(default=None)):
    """
    Red sends one in-flight prompt. Broker routes it to the model (fresh
    session), then to the blue guard for a verdict, pads the latency, audits
    metadata only, and returns the verdict to red. Blue sees ONLY this single
    prompt, never the committed corpus.
    """
    _auth(x_token, "red", "attack", "model")
    if state.phase != "running":
        raise HTTPException(409, "no running test")
    started = time.perf_counter()
    prompt = payload["prompt"]
    idx = payload.get("index", len(state.results))

    async with httpx.AsyncClient(timeout=30) as client:
        # 1) model lane produces a completion in its ephemeral session
        m = await client.post(f"{MODEL_URL}/complete",
                              json={"session": state.model_session, "prompt": prompt})
        completion = m.json().get("completion", "")
        # 2) blue guard scores the single in-flight exchange
        b = await client.post(f"{BLUE_URL}/score",
                             json={"prompt": prompt, "completion": completion})
        verdict = b.json()

    blocked = bool(verdict.get("blocked"))
    state.verdicts["blocked" if blocked else "allowed"] += 1
    # audit stores a HASH of the prompt (commitment linkage) + metadata, not text
    import hashlib
    state.results.append({"index": idx, "blocked": blocked,
                          "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16]})
    audit.append("broker", "attack_routed",
                 {"test_id": state.test_id, "index": idx, "blocked": blocked,
                  "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()})
    feed("attack", index=idx, blocked=blocked)
    pad_ms = await padder.pad(started)   # fixed-latency quantization
    return {"index": idx, "blocked": blocked, "reason": verdict.get("reason"),
            "pad_ms": round(pad_ms, 2)}


@app.post("/test/close")
async def close_test(x_token: str | None = Header(default=None)):
    _auth(x_token, "operator", "close_test", "broker")
    state.phase = "closed"
    audit.append("operator", "close_test", {"test_id": state.test_id,
                 "attacks": len(state.results), "verdicts": state.verdicts})
    feed("close_test", attacks=len(state.results))
    return {"phase": state.phase, "verdicts": state.verdicts}


@app.post("/reveal")
async def reveal(payload: dict, x_token: str | None = Header(default=None)):
    """Red reveals (nonce, payloads) AFTER close. Broker verifies the commitment."""
    _auth(x_token, "red", "reveal", "broker")
    if state.phase != "closed":
        raise HTTPException(409, "reveal only after test close")
    ok = verify_reveal(state.commitment.commitment, payload["nonce"], payload["payloads"])
    state.commitment.revealed = ok
    audit.append("red", "reveal",
                 {"test_id": state.test_id, "commitment_valid": ok,
                  "n_revealed": len(payload["payloads"])})
    feed("reveal", commitment_valid=ok)
    if not ok:
        raise HTTPException(400, "reveal does not match commitment — payloads were altered")
    return {"commitment_valid": True, "n_payloads": len(payload["payloads"])}


# --------------------------------------------------------------------------- #
# Audit / sealing / verification
# --------------------------------------------------------------------------- #
@app.post("/seal")
async def seal(x_token: str | None = Header(default=None)):
    _auth(x_token, "operator", "seal", "broker")
    result = audit.seal()
    feed("seal", merkle_root=result["merkle_root"][:16])
    return result


@app.get("/audit/export")
async def audit_export():
    return audit.export()


@app.get("/report")
async def isolation_report():
    """
    Emit a signed **isolation attestation** — the product's actual deliverable.

    It bundles, for the current test, the results that matter to a safety
    finding (block rate, measured cross-lane canary leakage, the audit Merkle
    root) plus an explicit residual-risk statement, and signs the whole bundle
    with the audit key. Anyone can recompute the hash and verify the signature
    with `common/report.py`, so a third party can trust the finding without
    trusting us. This is what makes a safety result independently defensible.

    Read-only: it signs the report over the CURRENT audit Merkle root but does
    NOT persist a new seal — persisting a seal is an authenticated operator
    action (`POST /seal`), so this public endpoint cannot mutate the log.
    """
    from common.audit import merkle_root
    current_root = merkle_root(audit.all_hashes())
    total = max(1, state.verdicts["blocked"] + state.verdicts["allowed"])
    cr = state.canary_report or {}
    body = {
        "arena": "chakravyuh",
        "test_id": state.test_id,
        "model_session": state.model_session,
        "attacks_processed": len(state.results),
        "block_rate": round(state.verdicts["blocked"] / total, 3),
        "verdicts": state.verdicts,
        "canary_leaks": cr.get("leaks_found"),
        "canary_probes": cr.get("probes_run"),
        "payloads_commitment_verified": bool(state.commitment and state.commitment.revealed),
        "audit_merkle_root": current_root,
        "audit_records": len(audit.all_hashes()),
        "latency_quantum_ms": padder.quantum_ms,
        "protects_against": [
            "cross-lane payload/logic/weight leakage (network, fs, env, process)",
            "early payload disclosure to blue (commit-reveal)",
            "cross-test model contamination (ephemeral sessions)",
            "audit tampering (hash chain + signed Merkle root)",
        ],
        "does_not_protect_against": [
            "shared host kernel / container-runtime 0-days",
            "microarchitectural side channels on shared CPU/GPU",
            "a malicious host operator or root",
        ],
    }
    from common.report import sign_report
    signed = sign_report(body, audit._key)
    signed["public_key"] = audit.public_key_hex
    feed("report", block_rate=body["block_rate"], canary_leaks=body["canary_leaks"])
    return signed


# --------------------------------------------------------------------------- #
# Canary leak report ingestion (probes POST their findings here)
# --------------------------------------------------------------------------- #
@app.post("/canary/report")
async def canary_report(report: dict, x_token: str | None = Header(default=None)):
    # A least-privilege 'prober' principal may submit a leakage report and
    # nothing else — it cannot open tests, attack, or read the audit key.
    _auth(x_token, "prober", "canary", "broker")
    state.canary_report = report
    audit.append("operator", "canary_report",
                 {"leaks": report.get("leaks_found"),
                  "probes": report.get("probes_run")})
    feed("canary", leaks=report.get("leaks_found"), probes=report.get("probes_run"))
    return {"recorded": True}


# --------------------------------------------------------------------------- #
# Metadata-only observability (vertical 7: monitoring that does not leak)
# --------------------------------------------------------------------------- #
@app.get("/state")
async def get_state():
    return state.snapshot()


@app.get("/events")
async def get_events():
    return {"events": events[-100:], "padding": {
        "quantum_ms": padder.quantum_ms, "avg_pad_ms": round(padder.stats.avg_pad_ms, 2),
        "requests": padder.stats.requests}}


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    from dashboard.page import PAGE
    return PAGE
