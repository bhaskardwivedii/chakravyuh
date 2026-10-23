"""
Regenerate tests/verifier/fixtures.json from the arena's own Python code, so the
browser verifier is tested against the exact bytes Python produces.

    PYTHONPATH=. python3 tests/verifier/make_fixtures.py
"""
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.audit import canonical, merkle_root, record_hash

CASES = [
    {"quantum_ms": 50.0, "policy": "/app/broker/policy/policy.yaml"},
    {"small": 1e-05, "big": 1e16, "neg_zero": -0.0, "int": 7, "neg": -3, "frac": 0.333},
    {"ts": 1792757806.97597, "rate": 0.5, "one": 1.0},
    {"dash": "isolation — measured", "accent": "café", "emoji": "lock \U0001F512"},
    {"ctrl": "tab\there\nnew\rcr\bbs\ffeed\x01\x1f\x7f", "q": 'say "hi" \\ path/x'},
    {"Zeta": 1, "alpha": 2, "Alpha": 3, "_u": 4, "10": 5, "9": 6},
    {"nested": {"b": [1, {"z": None, "a": True}, False], "a": []}, "empty": {}},
    {"unicode_key_é": "v", "list": [" ", " ", "x"]},
]


def main():
    out = {"canonical": [], "merkle": [], "record_hash": [], "ed25519": {}}
    for obj in CASES:
        canon = canonical(obj).decode()
        out["canonical"].append({
            # the same object as Python would send it over HTTP, two ways
            "source_ascii": json.dumps(obj),
            "source_utf8": json.dumps(obj, ensure_ascii=False, separators=(",", ":")),
            "canonical": canon,
            "sha256": hashlib.sha256(canon.encode()).hexdigest(),
        })
    leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(7)]
    for n in range(0, 8):
        out["merkle"].append({"leaves": leaves[:n], "root": merkle_root(leaves[:n])})
    ev = {"actor": "broker", "action": "startup", "detail": {"quantum_ms": 50.0, "note": "—"}}
    out["record_hash"].append({
        "source": json.dumps({"prev": "0" * 64, "seq": 0, "ts": 1792757806.97597, "event": ev},
                             ensure_ascii=False),
        "hash": record_hash("0" * 64, 0, 1792757806.97597, ev),
    })
    key = Ed25519PrivateKey.generate()
    msg = bytes.fromhex(leaves[3])
    out["ed25519"] = {
        "public_key": key.public_key().public_bytes_raw().hex(),
        "message_hex": msg.hex(),
        "signature": key.sign(msg).hex(),
    }
    path = os.path.join(os.path.dirname(__file__), "fixtures.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", path)


if __name__ == "__main__":
    main()
