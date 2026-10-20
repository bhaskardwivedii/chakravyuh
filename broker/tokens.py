"""
Capability tokens for the broker (vertical 3: Access Control & Secrets).

Short-lived, signed, least-privilege tokens. Each lane is issued only the
capabilities its role needs for the current phase. Tokens are HMAC-signed by the
broker so lanes cannot forge or escalate them, and they carry an expiry so a
leaked token is useless after the test window.

We use a symmetric HMAC (broker is both issuer and verifier) rather than a full
PKI, which is sufficient because only the broker validates tokens. The payload
is non-secret (it lists granted capabilities); the signature is what matters.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import time


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenIssuer:
    def __init__(self, secret: bytes):
        self._secret = secret

    def issue(self, subject: str, capabilities: list[str], ttl: int = 3600) -> str:
        body = {"sub": subject, "cap": capabilities, "exp": time.time() + ttl}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(self._secret, raw, hashlib.sha256).digest()
        return f"{_b64(raw)}.{_b64(sig)}"

    def verify(self, token: str) -> dict | None:
        """Return the token body if valid and unexpired, else None."""
        try:
            raw_b64, sig_b64 = token.split(".")
            raw, sig = _unb64(raw_b64), _unb64(sig_b64)
        except (ValueError, Exception):
            return None
        expected = hmac.new(self._secret, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        body = json.loads(raw)
        if body.get("exp", 0) < time.time():
            return None
        return body
