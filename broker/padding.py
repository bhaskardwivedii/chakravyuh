"""
Fixed-latency response padding (objective 05 / vertical 5 & 6).

LLM-native timing side channels (e.g. the NDSS 2025 "PromptPeek" KV-cache
timing attack) let one tenant infer another's prompt/state from response-time
variation. The broker blunts this by quantizing every response to a fixed time
quantum: it measures how long the real work took and sleeps until the next
multiple of `quantum_ms`, so an observer sees a near-constant latency regardless
of cache hits, prompt length or model internal state.

This does not eliminate side channels (a dedicated attacker can still exploit
microarchitectural effects — see the threat model), but it removes the trivial
wall-clock signal and makes timing inference substantially harder and noisier.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class PaddingStats:
    requests: int = 0
    total_pad_ms: float = 0.0

    @property
    def avg_pad_ms(self) -> float:
        return self.total_pad_ms / self.requests if self.requests else 0.0


class LatencyPadder:
    def __init__(self, quantum_ms: float = 50.0):
        self.quantum_ms = quantum_ms
        self.stats = PaddingStats()

    async def pad(self, started_at: float) -> float:
        """Await until elapsed time is a multiple of the quantum. Returns pad ms."""
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        # round up to the next quantum boundary
        target = (int(elapsed_ms // self.quantum_ms) + 1) * self.quantum_ms
        pad_ms = max(0.0, target - elapsed_ms)
        self.stats.requests += 1
        self.stats.total_pad_ms += pad_ms
        await asyncio.sleep(pad_ms / 1000.0)
        return pad_ms
