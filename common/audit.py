"""
Tamper-evident audit log for the Chakravyuh arena.

Addresses Hack in Hills '26 Track 04 objective 03 ("Guarantee Audit Integrity")
and recommended vertical 4 ("Audit Trails & Forensic Provenance").

Design
------
Every security-relevant event is appended to an *append-only* log. Each record
carries the SHA-256 hash of the previous record, so the log forms a hash chain:
changing, reordering or deleting any past record breaks every hash after it.

At defined checkpoints (and at test close) the broker seals the chain by
computing a Merkle root over all records so far and signing that root with an
Ed25519 key. The signed root is the single value an external auditor needs: if
they recompute the Merkle root from the records and the signature verifies, the
entire history is proven intact. Optionally the root can be anchored to a public
testnet so even the arena operator cannot rewrite history unnoticed.

The verifier (`verify_chain`) is deliberately dependency-light so a third party
can re-run it against an exported log without trusting our code.
"""
from __future__ import annotations

import json
import hashlib
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

GENESIS = "0" * 64


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding so hashes are reproducible across machines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def record_hash(prev_hash: str, seq: int, ts: float, event: dict) -> str:
    """Hash binding a record to its position and to the whole prior history."""
    return _h(canonical({"prev": prev_hash, "seq": seq, "ts": ts, "event": event}))


# --------------------------------------------------------------------------- #
# Merkle tree over record hashes
# --------------------------------------------------------------------------- #
def merkle_root(leaves: list[str]) -> str:
    """Merkle root of the leaf hashes. Odd nodes are duplicated (Bitcoin-style)."""
    if not leaves:
        return GENESIS
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_h(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
    return level[0]


@dataclass
class Record:
    seq: int
    ts: float
    actor: str          # which lane / component emitted this
    action: str         # e.g. commit, open_test, attack, verdict, reveal, canary
    detail: dict        # metadata ONLY — never raw payload content (see note)
    prev_hash: str
    hash: str

    def to_row(self) -> tuple:
        return (self.seq, self.ts, self.actor, self.action,
                json.dumps(self.detail, sort_keys=True), self.prev_hash, self.hash)


# NOTE on content: the audit log stores *metadata and commitments*, not raw
# attack payloads or model outputs. Payloads are represented by their hash
# commitment (commit-reveal); this keeps the observability/audit layer from
# becoming an information-leakage channel (objective 02 / vertical 7).
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq       INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    actor     TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    detail    TEXT    NOT NULL,
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS seals (
    seq         INTEGER PRIMARY KEY,   -- records sealed up to and including this seq
    ts          REAL NOT NULL,
    merkle_root TEXT NOT NULL,
    signature   TEXT NOT NULL,         -- hex Ed25519 signature over merkle_root
    anchor      TEXT                   -- optional external anchor (e.g. testnet txid)
);
"""


class AuditLog:
    """Append-only, hash-chained, signable audit log backed by SQLite."""

    def __init__(self, db_path: str, signing_key: Optional[Ed25519PrivateKey] = None):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._key = signing_key or Ed25519PrivateKey.generate()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @property
    def public_key_hex(self) -> str:
        return self._key.public_key().public_bytes_raw().hex()

    def _last(self) -> tuple[int, str]:
        cur = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        return (row[0], row[1]) if row else (-1, GENESIS)

    def append(self, actor: str, action: str, detail: dict) -> Record:
        last_seq, prev_hash = self._last()
        seq = last_seq + 1
        ts = time.time()
        h = record_hash(prev_hash, seq, ts, {"actor": actor, "action": action, "detail": detail})
        rec = Record(seq, ts, actor, action, detail, prev_hash, h)
        self._conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?,?,?)", rec.to_row())
        self._conn.commit()
        return rec

    def all_hashes(self) -> list[str]:
        return [r[0] for r in self._conn.execute("SELECT hash FROM audit ORDER BY seq")]

    def seal(self, anchor: Optional[str] = None) -> dict:
        """Compute and sign a Merkle root over the whole chain so far."""
        hashes = self.all_hashes()
        root = merkle_root(hashes)
        sig = self._key.sign(bytes.fromhex(root)).hex()
        last_seq, _ = self._last()
        self._conn.execute(
            "INSERT OR REPLACE INTO seals VALUES (?,?,?,?,?)",
            (last_seq, time.time(), root, sig, anchor))
        self._conn.commit()
        return {"sealed_through_seq": last_seq, "merkle_root": root,
                "signature": sig, "public_key": self.public_key_hex, "anchor": anchor}

    def export(self) -> dict:
        """Export the full log + latest seal for independent verification."""
        records = [dict(zip(
            ["seq", "ts", "actor", "action", "detail", "prev_hash", "hash"],
            (r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6])))
            for r in self._conn.execute(
                "SELECT seq,ts,actor,action,detail,prev_hash,hash FROM audit ORDER BY seq")]
        seal_row = self._conn.execute(
            "SELECT seq,ts,merkle_root,signature,anchor FROM seals ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seal = None
        if seal_row:
            seal = {"sealed_through_seq": seal_row[0], "ts": seal_row[1],
                    "merkle_root": seal_row[2], "signature": seal_row[3],
                    "anchor": seal_row[4]}
        return {"public_key": self.public_key_hex, "records": records, "seal": seal}


# --------------------------------------------------------------------------- #
# Independent verifier — no arena code or state required beyond the export
# --------------------------------------------------------------------------- #
def verify_chain(export: dict) -> dict:
    """
    Re-derive every hash and the Merkle root from an exported log and check the
    Ed25519 seal. Returns a structured result an auditor can act on.
    """
    records = export["records"]
    problems: list[str] = []
    prev = GENESIS
    recomputed: list[str] = []

    for i, r in enumerate(records):
        if r["seq"] != i:
            problems.append(f"seq gap/reorder at index {i}: seq={r['seq']}")
        if r["prev_hash"] != prev:
            problems.append(f"broken link at seq {r['seq']}: prev_hash mismatch")
        expect = record_hash(
            prev, r["seq"], r["ts"],
            {"actor": r["actor"], "action": r["action"], "detail": r["detail"]})
        if expect != r["hash"]:
            problems.append(f"content tampered at seq {r['seq']}: hash mismatch")
        prev = r["hash"]
        recomputed.append(r["hash"])

    seal = export.get("seal")
    sig_ok = False
    root_ok = False
    if seal:
        root = merkle_root(recomputed[: seal["sealed_through_seq"] + 1])
        root_ok = (root == seal["merkle_root"])
        if not root_ok:
            problems.append("merkle root does not match sealed records")
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(export["public_key"]))
            pub.verify(bytes.fromhex(seal["signature"]), bytes.fromhex(seal["merkle_root"]))
            sig_ok = True
        except (InvalidSignature, ValueError):
            problems.append("Ed25519 seal signature invalid")
    else:
        problems.append("no seal present")

    return {"valid": not problems, "records_checked": len(records),
            "chain_intact": all("tampered" not in p and "link" not in p and "reorder" not in p
                                for p in problems),
            "merkle_root_ok": root_ok, "signature_ok": sig_ok, "problems": problems}
