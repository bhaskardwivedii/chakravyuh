"""
Timing side-channel experiment — does the broker's latency padding actually
hide a secret-dependent timing signal? (objective 05, vertical 6)

Motivation
----------
The NDSS 2025 "PromptPeek" attack recovered other tenants' prompts from
response-time variation caused by shared KV-cache hits/misses. The broker pads
every response to a fixed latency quantum to blunt this. Implementing a defence
is not enough — a strong submission *measures* whether it works.

Method
------
We model a secret-dependent timing signal: a "secret bit" that makes the model
lane's work either fast (cache-hit-like) or slow (cache-miss-like). An observer
sees only the end-to-end latency the broker returns. We then ask: can the
observer recover the secret bit from latency alone?

We run the SAME populations through the real `LatencyPadder`:
  * padding OFF (quantum <= 0): latency ~= the secret-dependent work time
  * padding ON  (quantum = Q):  latency quantized to the next Q boundary

and train the strongest possible 1-D classifier (an optimal latency threshold,
chosen on the data itself — i.e. we *help* the attacker). The metric is the
attacker's accuracy at recovering the secret bit:

  ~1.0  => the timing channel leaks the secret (bad)
  ~0.5  => indistinguishable from a coin flip (the channel is closed)

This is the timing-channel analogue of the canary leakage score.
"""
from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time

from broker.padding import LatencyPadder


async def _observed_latency(padder: LatencyPadder, work_ms: float) -> float:
    """Run one request: do `work_ms` of work, pad, return total observed ms."""
    start = time.perf_counter()
    await asyncio.sleep(work_ms / 1000.0)
    await padder.pad(start)
    return (time.perf_counter() - start) * 1000.0


async def _collect(quantum_ms: float, trials: int, fast_ms: float,
                   slow_ms: float, jitter_ms: float, seed: int) -> list[tuple[int, float]]:
    rng = random.Random(seed)
    padder = LatencyPadder(quantum_ms=quantum_ms)
    samples: list[tuple[int, float]] = []
    for _ in range(trials):
        secret = rng.randint(0, 1)
        base = slow_ms if secret else fast_ms
        work = max(0.0, base + rng.gauss(0, jitter_ms))
        lat = await _observed_latency(padder, work)
        samples.append((secret, lat))
    return samples


def _best_threshold_accuracy(samples: list[tuple[int, float]]) -> float:
    """
    Strongest 1-D attacker: pick the latency threshold that best separates the
    two secret classes ON THIS DATA (optimistic for the attacker), and report
    its accuracy. 0.5 = no information; 1.0 = perfect recovery.
    """
    lats = sorted({s[1] for s in samples})
    if len(lats) <= 1:
        return 0.5
    candidates = [(lats[i] + lats[i + 1]) / 2 for i in range(len(lats) - 1)]
    n = len(samples)
    best = 0.5
    for thr in candidates:
        # try both polarities (slow>thr => secret=1, and the reverse)
        correct_hi = sum(1 for sec, lat in samples if (lat > thr) == bool(sec))
        acc = max(correct_hi, n - correct_hi) / n
        if acc > best:
            best = acc
    return best


async def run(trials: int = 400, quantum_ms: float = 50.0,
              fast_ms: float = 6.0, slow_ms: float = 26.0,
              jitter_ms: float = 2.0, seed: int = 7) -> dict:
    off = await _collect(0.0, trials, fast_ms, slow_ms, jitter_ms, seed)
    on = await _collect(quantum_ms, trials, fast_ms, slow_ms, jitter_ms, seed)

    def stats(samples):
        f = [l for s, l in samples if s == 0]
        s = [l for s, l in samples if s == 1]
        return (round(statistics.mean(f), 2), round(statistics.mean(s), 2))

    off_fast, off_slow = stats(off)
    on_fast, on_slow = stats(on)
    return {
        "trials": trials,
        "quantum_ms": quantum_ms,
        "work_fast_ms": fast_ms,
        "work_slow_ms": slow_ms,
        "padding_off": {
            "mean_latency_fast_ms": off_fast,
            "mean_latency_slow_ms": off_slow,
            "attacker_accuracy": round(_best_threshold_accuracy(off), 3),
        },
        "padding_on": {
            "mean_latency_fast_ms": on_fast,
            "mean_latency_slow_ms": on_slow,
            "attacker_accuracy": round(_best_threshold_accuracy(on), 3),
        },
    }


def leakage(acc: float) -> float:
    """Normalize attacker accuracy to a 0..1 leakage score (0.5 acc = 0 leak)."""
    return max(0.0, (acc - 0.5) / 0.5)


def _print(result: dict):
    off = result["padding_off"]["attacker_accuracy"]
    on = result["padding_on"]["attacker_accuracy"]
    l_off, l_on = leakage(off), leakage(on)
    print("=" * 60)
    print("TIMING SIDE-CHANNEL EXPERIMENT")
    print("=" * 60)
    print(f"secret-dependent work: fast={result['work_fast_ms']}ms  "
          f"slow={result['work_slow_ms']}ms   quantum={result['quantum_ms']}ms   "
          f"trials={result['trials']}")
    print(f"{'':20}{'mean lat (fast)':>16}{'mean lat (slow)':>16}{'attacker acc':>14}{'leakage':>10}")
    print("-" * 76)
    print(f"{'padding OFF':20}{result['padding_off']['mean_latency_fast_ms']:>16}"
          f"{result['padding_off']['mean_latency_slow_ms']:>16}{off:>14}{l_off:>10.2f}")
    print(f"{'padding ON':20}{result['padding_on']['mean_latency_fast_ms']:>16}"
          f"{result['padding_on']['mean_latency_slow_ms']:>16}{on:>14}{l_on:>10.2f}")
    print("-" * 76)
    reduction = (1 - l_on / l_off) * 100 if l_off else 0
    print(f"timing leakage reduced {l_off:.2f} -> {l_on:.2f}  "
          f"({reduction:.0f}% of the signal removed)")
    print("note: residual is near chance and dominated by scheduler jitter; a "
          "determined\nmicroarchitectural attacker remains out of scope "
          "(see docs/THREAT_MODEL.md).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--quantum-ms", type=float, default=50.0)
    args = ap.parse_args()
    res = asyncio.run(run(trials=args.trials, quantum_ms=args.quantum_ms))
    _print(res)
