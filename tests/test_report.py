"""The signed isolation report must be verifiable and tamper-evident."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.report import sign_report, verify_report


def _signed():
    key = Ed25519PrivateKey.generate()
    body = {"arena": "chakravyuh", "block_rate": 0.5, "canary_leaks": 0,
            "audit_merkle_root": "ab" * 32}
    signed = sign_report(body, key)
    signed["public_key"] = key.public_key().public_bytes_raw().hex()
    return signed


def test_valid_report_verifies():
    assert verify_report(_signed())["valid"] is True


def test_tampered_body_detected():
    signed = _signed()
    signed["report"]["canary_leaks"] = 5          # falsify a result
    r = verify_report(signed)
    assert r["valid"] is False
    assert any("hash" in p for p in r["problems"])


def test_forged_signature_detected():
    signed = _signed()
    signed["signature"] = "00" * 64
    r = verify_report(signed)
    assert r["valid"] is False
    assert r["signature_ok"] is False
