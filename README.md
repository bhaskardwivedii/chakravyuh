# Chakravyuh

**A sealed multi-tenant arena for trustworthy adversarial AI-safety testing.**
Hack in Hills '26 · Track 04 — *Securing Adversarial AI Safety Testing
Infrastructure (Bayora)*

> A safety finding is only as trustworthy as the isolation behind it.

Bayora runs a red team, a blue team and a client LLM together in one shared
Docker sandbox. That co-location is the problem: if red's payloads leak to blue,
or blue's logic leaks to red, or the model is contaminated between tests, every
"pass" or "fail" it produces is meaningless. Chakravyuh turns that shared
sandbox into **three sealed lanes bridged by one policy-enforcing broker**, and —
the part most submissions skip — it makes the isolation a **number you can
measure** instead of a claim you have to trust.

---

## The one-minute version

- **Three sealed lanes.** Red, blue and the client LLM each run in a rootless,
  seccomp-confined, capability-dropped container on its **own internal network**.
  No lane can route to another.
- **One broker.** The only path between lanes. It enforces a **default-deny**
  policy, issues least-privilege **capability tokens**, runs **commit-reveal** so
  blue never sees red's payloads before a test closes, starts a **fresh model
  session** per test, and **pads response latency** to blunt timing channels.
- **A verifiable record.** Every security event is written to a hash-chained log
  sealed with an **Ed25519-signed Merkle root**. An independent verifier replays
  it; tampering, reordering or deletion is detected.
- **Isolation you can measure.** An insider **canary-probe** suite plants secret
  tokens in each lane and tries to steal them from the others. The score is the
  number recovered. **Target: 0.**

**Measured result (reproducible):** the same probe suite recovers **4 canaries on
the insecure baseline and 0 on the hardened arena**, the audit trail verifies
end-to-end, and a denied syscall (`unshare`) is provably blocked even with full
capabilities. See [`docs/RESULTS.md`](docs/RESULTS.md).

---

## Quick start

```bash
# Full demo: build, boot, run a red/blue/model test, seal + verify the audit log
bash scripts/demo.sh
# open http://localhost:8000/  for the live isolation dashboard

# The headline benchmark: canary leakage, hardened vs insecure baseline
bash scripts/benchmark.sh

# Unit + integration tests (no Docker needed)
pip install -r docker/requirements.txt pytest
PYTHONPATH=. pytest -q
```

Requirements: Docker + Docker Compose. Everything runs on `python:3.12-slim`;
no GPU, no model download, no proprietary hardware. (By default a deterministic
mock "model" is used so the arena runs anywhere; set `OLLAMA_URL` in
`docker-compose.yml` to test a real small model such as `llama3.2:1b`.)

---

## Architecture

Five layers — **isolate, segment, broker, record, observe**:

```
   RED lane            BROKER (sole bridge)                 BLUE lane
 ┌───────────┐   ┌──────────────────────────────┐        ┌───────────┐
 │ rootless  │   │ default-deny policy (OPA-style)│       │ rootless  │
 │ seccomp   │◀─▶│ capability tokens              │◀─────▶│ seccomp   │
 │ commit    │   │ commit-reveal enforcement      │       │ verdict   │
 │ -reveal   │   │ fixed-latency padding          │       │ only      │
 └───────────┘   │ hash-chained signed audit log  │       └───────────┘
   net-red       │ metadata-only observability    │         net-blue
                 └───────────────┬────────────────┘
                                 │ net-model
                           ┌───────────┐
                           │  MODEL    │  fresh ephemeral session per test
                           │ (no KV    │  (no cross-test contamination)
                           │  carryover)│
                           └───────────┘
```

| Layer | What it does | Code |
|-------|--------------|------|
| **Isolate** | rootless containers, seccomp allowlist, `cap_drop ALL`, read-only FS, cgroup limits | `docker-compose.yml`, `docker/seccomp/` |
| **Segment** | one internal network per lane; broker is the only bridge | `docker-compose.yml` |
| **Broker** | policy, tokens, commit-reveal, latency padding | `broker/` |
| **Record** | hash-chained, Ed25519-sealed audit log + independent verifier | `common/audit.py` |
| **Observe** | metadata-only dashboard, canary leak score | `dashboard/`, `probes/` |

Full requirement-by-requirement mapping to the 6 objectives and 7 verticals:
[`docs/OBJECTIVES.md`](docs/OBJECTIVES.md). Trust boundaries and residual risk:
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## What's novel here

1. **Isolation as a tested property, not an assumption.** The canary suite gives
   a single falsifiable number. Most isolation work asserts boundaries; we probe
   them from the inside and report what got through.
2. **Commit-reveal for the red/blue protocol.** Red binds its corpus with a hash
   before the test and reveals it only after close — blue can't peek, red can't
   swap. This is a protocol-level fix, not just a network rule.
3. **An audit layer that doesn't leak.** Observability is metadata-only by
   construction: the log stores payload *hashes*, never payload text (verified).
4. **Honest, measured guarantees.** A written residual-risk model paired with a
   reproducible leakage score — directly answering objective 06, which most
   teams will treat as an afterthought.

---

## How the datasets drop in

The sample red payloads mirror the structure of the brief's suggested datasets.
To run the real corpora, point `PAYLOAD_FILE` (in the `red` service) at a
newline-delimited export of **JailbreakBench**, **AdvBench** or **HarmBench**
prompts; **ToxiGen**/**HH-RLHF** give a benign baseline for false-positive rates;
**NVD/CVE** container-escape entries inform the threat model. No code change
needed.

---

## Repository layout

```
broker/        FastAPI broker: policy engine, capability tokens, commit-reveal,
               latency padding, audit + canary endpoints, dashboard route
common/        audit log (hash chain + Merkle + Ed25519 + verifier), commit-reveal
lanes/         model (ephemeral sessions), blue (guard/scorer), red (attack agent)
probes/        canary insider-probe suite (network/fs/env/process channels)
dashboard/     single-file metadata-only isolation dashboard
docker/        Dockerfile, requirements, entrypoint, seccomp profile (+ empirical set)
scripts/       demo.sh (one-command demo), benchmark.sh (leakage benchmark)
tests/         31 pytest cases: audit, commit-reveal, policy, tokens, padding, e2e
docs/          OBJECTIVES.md, THREAT_MODEL.md, RESULTS.md, DEMO.md
docker-compose.yml           hardened arena
docker-compose.insecure.yml  insecure baseline (for the benchmark)
```

## Team

**Team Chakravyuh** 

## Security note

`BROKER_SECRET` defaults to a development value — set a strong secret via the
environment before any real deployment. This is a hackathon proof of concept;
see the residual-risk section before trusting it with real safety evaluations.
