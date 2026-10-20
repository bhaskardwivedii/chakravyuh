"""Tests for the tamper-evident audit log (objective 03)."""
import os
import tempfile

from common.audit import AuditLog, verify_chain, merkle_root, GENESIS


def _fresh_log():
    d = tempfile.mkdtemp()
    return AuditLog(os.path.join(d, "audit.db"))


def test_chain_and_seal_verify_clean():
    log = _fresh_log()
    for i in range(10):
        log.append("broker", "attack_routed", {"index": i, "blocked": i % 2 == 0})
    log.seal()
    result = verify_chain(log.export())
    assert result["valid"] is True
    assert result["signature_ok"] is True
    assert result["merkle_root_ok"] is True
    assert result["records_checked"] == 10


def test_content_tampering_is_detected():
    log = _fresh_log()
    for i in range(5):
        log.append("red", "commit", {"n": i})
    log.seal()
    export = log.export()
    # Flip a byte of a past record's detail — classic log-tampering attempt.
    export["records"][2]["detail"] = {"n": 999}
    result = verify_chain(export)
    assert result["valid"] is False
    assert result["chain_intact"] is False
    assert any("tampered" in p for p in result["problems"])


def test_record_deletion_is_detected():
    log = _fresh_log()
    for i in range(6):
        log.append("broker", "event", {"i": i})
    log.seal()
    export = log.export()
    del export["records"][3]              # drop a record
    result = verify_chain(export)
    assert result["valid"] is False       # seq gap + broken link + root mismatch


def test_reorder_is_detected():
    log = _fresh_log()
    for i in range(4):
        log.append("broker", "event", {"i": i})
    log.seal()
    export = log.export()
    export["records"][1], export["records"][2] = export["records"][2], export["records"][1]
    result = verify_chain(export)
    assert result["valid"] is False


def test_forged_signature_fails():
    log = _fresh_log()
    log.append("broker", "event", {"i": 1})
    log.seal()
    export = log.export()
    # Attacker recomputes a matching root but cannot produce a valid Ed25519 sig.
    export["seal"]["signature"] = "00" * 64
    result = verify_chain(export)
    assert result["signature_ok"] is False
    assert result["valid"] is False


def test_merkle_root_stable_and_order_sensitive():
    a = ["aa" * 32, "bb" * 32, "cc" * 32]
    assert merkle_root(a) == merkle_root(a)              # deterministic
    assert merkle_root(a) != merkle_root(list(reversed(a)))
    assert merkle_root([]) == GENESIS
