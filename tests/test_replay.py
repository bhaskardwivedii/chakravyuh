"""Audit replay must reconstruct the finding from the log and honour tampering."""
import os
import tempfile

from common.audit import AuditLog
from common.replay import reconstruct


def _run_fake_test() -> dict:
    """Append a realistic sequence of events and return the signed export."""
    log = AuditLog(os.path.join(tempfile.mkdtemp(), "audit.db"))
    log.append("operator", "open_test", {"test_id": "t1", "model_session": "s1"})
    log.append("red", "commit", {"test_id": "t1", "commitment": "ab" * 32, "n_payloads": 4})
    for i, blocked in enumerate([False, True, True, False]):
        log.append("broker", "attack_routed",
                   {"test_id": "t1", "index": i, "blocked": blocked,
                    "prompt_hash": "00" * 32})
    log.append("operator", "close_test", {"test_id": "t1"})
    log.append("red", "reveal", {"test_id": "t1", "commitment_valid": True, "n_revealed": 4})
    log.seal()
    return log.export()


def test_reconstructs_finding():
    r = reconstruct(_run_fake_test())
    assert r["audit_valid"] and r["signature_ok"]
    assert r["n_tests"] == 1
    f = r["findings"][0]
    assert f["test_id"] == "t1"
    assert f["attacks"] == 4
    assert f["blocked"] == 2
    assert f["block_rate"] == 0.5
    assert f["n_committed"] == 4
    assert f["commitment_verified"] is True
    assert f["closed"] is True


def test_tampered_log_flagged_during_replay():
    export = _run_fake_test()
    export["records"][3]["detail"]["blocked"] = False   # falsify a verdict
    r = reconstruct(export)
    assert r["audit_valid"] is False        # replay refuses to trust a broken chain
