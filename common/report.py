"""
Signed isolation report — sign and independently verify the arena's attestation.

The broker's /report endpoint produces a signed bundle of the results that back
a safety finding (block rate, canary leakage, audit root, residual risk). This
module does the signing and the independent verification, so a third party can
confirm a report is authentic and unmodified without trusting the arena code.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

from .audit import canonical, _h


def sign_report(body: dict, key: Ed25519PrivateKey) -> dict:
    """Return {report, report_hash, signature} for a report body."""
    report_hash = _h(canonical(body))
    signature = key.sign(bytes.fromhex(report_hash)).hex()
    return {"report": body, "report_hash": report_hash, "signature": signature}


def verify_report(signed: dict) -> dict:
    """Recompute the hash and check the Ed25519 signature. No arena code trusted."""
    problems = []
    recomputed = _h(canonical(signed["report"]))
    if recomputed != signed["report_hash"]:
        problems.append("report hash does not match body (report was modified)")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["public_key"]))
        pub.verify(bytes.fromhex(signed["signature"]), bytes.fromhex(signed["report_hash"]))
        sig_ok = True
    except (InvalidSignature, ValueError, KeyError):
        sig_ok = False
        problems.append("signature invalid")
    return {"valid": not problems, "signature_ok": sig_ok, "problems": problems}
