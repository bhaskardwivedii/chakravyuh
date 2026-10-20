"""Tests for capability tokens, latency padding, and canary-probe logic."""
import asyncio
import time

from broker.tokens import TokenIssuer
from broker.padding import LatencyPadder
from probes.canary import run_probes, ProbeResult


# ---- capability tokens ----------------------------------------------------- #
def test_token_roundtrip():
    iss = TokenIssuer(b"secret")
    tok = iss.issue("red", ["red.attack"])
    body = iss.verify(tok)
    assert body and body["sub"] == "red" and "red.attack" in body["cap"]


def test_token_forgery_rejected():
    iss = TokenIssuer(b"secret")
    tok = iss.issue("red", ["red.attack"])
    # Tamper with the payload; signature no longer matches.
    head, sig = tok.split(".")
    forged = head[:-2] + ("aa" if not head.endswith("aa") else "bb") + "." + sig
    assert iss.verify(forged) is None


def test_token_wrong_secret_rejected():
    tok = TokenIssuer(b"secret-A").issue("operator", ["operator.control"])
    assert TokenIssuer(b"secret-B").verify(tok) is None


def test_token_expiry():
    iss = TokenIssuer(b"secret")
    tok = iss.issue("red", ["red.attack"], ttl=-1)   # already expired
    assert iss.verify(tok) is None


# ---- latency padding ------------------------------------------------------- #
def test_padding_quantizes_latency():
    padder = LatencyPadder(quantum_ms=40)

    async def one(work_ms):
        start = time.perf_counter()
        await asyncio.sleep(work_ms / 1000)
        pad = await padder.pad(start)
        total = (time.perf_counter() - start) * 1000
        return total

    # Two very different workloads should land on quantum boundaries, so their
    # observable latencies are both multiples of the quantum (timing hidden).
    t_short = asyncio.run(one(5))
    t_long = asyncio.run(one(25))
    for t in (t_short, t_long):
        nearest = round(t / 40) * 40
        assert abs(t - nearest) < 15   # within scheduler jitter of a boundary


# ---- canary probe logic (in-process simulation of channels) ---------------- #
def test_canary_no_leak_when_isolated(monkeypatch, tmp_path):
    # Simulate an isolated lane: peers unreachable, no shared secret files,
    # no peer env, no peer processes.
    import probes.canary as c
    monkeypatch.setattr(c, "CANARY_PATHS", {"blue": str(tmp_path / "nope.canary")})
    res = run_probes("red", ["blue", "model"])
    # network probes to blue/model fail (nothing listening on those names here)
    assert res.leaks_found == 0
    assert res.probes_run > 0


def test_canary_detects_filesystem_leak(monkeypatch, tmp_path):
    import probes.canary as c
    leaky = tmp_path / "blue.canary"
    leaky.write_text("canary-blue-abc123")
    monkeypatch.setattr(c, "CANARY_PATHS", {"blue": str(leaky)})
    # Only run the filesystem channel to isolate the assertion.
    res = ProbeResult(probing_lane="red")
    c._try_filesystem("blue", res)
    assert res.leaks_found == 1
    assert res.findings[0]["channel"] == "filesystem"
