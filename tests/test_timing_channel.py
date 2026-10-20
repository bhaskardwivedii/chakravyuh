"""The latency padding must substantially reduce a secret-dependent timing channel."""
import asyncio

from probes.timing_channel import run, leakage


def test_padding_reduces_timing_leakage():
    # Lighter params than the standalone script so the suite stays fast; the
    # effect (strong channel off, near-chance on) is the same.
    result = asyncio.run(run(trials=150, quantum_ms=20.0,
                             fast_ms=3.0, slow_ms=12.0, jitter_ms=1.0, seed=7))
    off = result["padding_off"]["attacker_accuracy"]
    on = result["padding_on"]["attacker_accuracy"]
    # Without padding the secret bit is almost perfectly recoverable from latency.
    assert off >= 0.9, f"expected a strong channel with padding off, got {off}"
    # With padding the attacker is driven toward chance (big leakage reduction).
    assert leakage(on) <= 0.5 * leakage(off), (
        f"padding should cut timing leakage by >=50%, off={off} on={on}")
    # Padding also collapses the mean latencies the observer sees.
    on_fast = result["padding_on"]["mean_latency_fast_ms"]
    on_slow = result["padding_on"]["mean_latency_slow_ms"]
    assert abs(on_fast - on_slow) < 5.0, "padded means should be close together"
