"""
Commit-reveal protocol for red-team attack payloads.

Addresses the Track 04 requirement:
  "Red-team attack payloads must not be observable by the blue team before a
   test concludes" and "Blue-team defensive logic must not be ... inferable".

Flow
----
1. Before a test opens, the red lane computes a commitment for its payload set:
       commitment = SHA-256( nonce || canonical(payloads) )
   and submits ONLY the commitment hash to the broker. The broker records it in
   the audit log. Blue never sees the payloads at this stage.

2. During the test, individual payloads are delivered to the model lane through
   the broker one at a time; blue sees only the broker's sanitized verdict
   stream, not the payload corpus.

3. After the test closes, red reveals (nonce, payloads). The broker recomputes
   the commitment and checks it equals the committed hash. This proves red could
   not swap payloads after seeing blue's behaviour, and gives blue the full
   corpus only once it can no longer bias the result.

This is a binding + hiding commitment: the nonce hides the payloads (so the
commitment leaks nothing about them), and SHA-256 pre-image/collision resistance
binds red to exactly what it committed.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .audit import canonical


def make_commitment(payloads: list[str], nonce: str | None = None) -> tuple[str, str]:
    """Return (nonce, commitment_hex) for a payload set."""
    nonce = nonce or secrets.token_hex(16)
    digest = hashlib.sha256(nonce.encode() + b"|" + canonical(payloads)).hexdigest()
    return nonce, digest


def verify_reveal(commitment: str, nonce: str, payloads: list[str]) -> bool:
    """Check that a reveal matches a previously published commitment."""
    _, recomputed = make_commitment(payloads, nonce)
    return secrets.compare_digest(recomputed, commitment)


@dataclass
class Commitment:
    test_id: str
    commitment: str
    n_payloads: int          # count is disclosed; contents are not
    revealed: bool = False
