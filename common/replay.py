"""
Audit replay — independently reconstruct a safety finding from the signed log.

Objective 03 asks that "safety findings can be independently reconstructed and
validated." Verification (common/audit.py) proves the log is intact; replay goes
the step further the brief asks for: it takes an exported, verified audit log and
*rebuilds the finding* — which test ran, how many attacks, how many the guard
blocked, whether red's payload commitment was honoured, and the sealed Merkle
root — purely from the recorded events, trusting no live arena state.

The reconstructed finding is deterministic from the log, so an auditor runs this
against the export and gets the same result the operator did, or detects a
discrepancy. Used by the CLI and by `scripts/*`.
"""
from __future__ import annotations

import argparse
import json

from .audit import verify_chain


def reconstruct(export: dict, test_id: str | None = None) -> dict:
    """Rebuild the finding(s) for a test purely from audit events."""
    chain = verify_chain(export)
    records = export["records"]

    # Group events by test_id (open_test announces it; later events carry it).
    tests: dict[str, dict] = {}
    current = None
    for r in records:
        d = r.get("detail", {})
        action = r["action"]
        tid = d.get("test_id")
        if action == "open_test" and tid:
            current = tid
            tests[tid] = {"test_id": tid, "model_session": d.get("model_session"),
                          "attacks": 0, "blocked": 0, "committed_hash": None,
                          "n_committed": None, "commitment_verified": None,
                          "closed": False, "events": 0}
        tid = tid or current
        if tid and tid in tests:
            t = tests[tid]
            t["events"] += 1
            if action == "commit":
                t["committed_hash"] = d.get("commitment")
                t["n_committed"] = d.get("n_payloads")
            elif action == "attack_routed":
                t["attacks"] += 1
                t["blocked"] += int(bool(d.get("blocked")))
            elif action == "close_test":
                t["closed"] = True
            elif action == "reveal":
                t["commitment_verified"] = bool(d.get("commitment_valid"))

    findings = []
    for t in tests.values():
        total = max(1, t["attacks"])
        findings.append({**t, "block_rate": round(t["blocked"] / total, 3)})

    if test_id:
        findings = [f for f in findings if f["test_id"] == test_id]

    return {
        "audit_valid": chain["valid"],
        "signature_ok": chain["signature_ok"],
        "merkle_root": (export.get("seal") or {}).get("merkle_root"),
        "n_tests": len(findings),
        "findings": findings,
    }


def _print(result: dict):
    status = "VALID" if result["audit_valid"] and result["signature_ok"] else "INVALID"
    print("=" * 60)
    print(f"AUDIT REPLAY — reconstructed finding(s)   [audit: {status}]")
    print("=" * 60)
    if not result["audit_valid"]:
        print("  ! audit chain did not verify — finding cannot be trusted")
    root = result["merkle_root"]
    print(f"  sealed merkle root: {root[:32]+'…' if root else '(unsealed)'}")
    for f in result["findings"]:
        print("-" * 60)
        print(f"  test {f['test_id']}  (model session {f['model_session']})")
        print(f"    attacks reconstructed .... {f['attacks']}")
        print(f"    blocked by guard ......... {f['blocked']}  (block rate {f['block_rate']})")
        print(f"    payload commitment ....... {f['committed_hash'][:16]+'…' if f['committed_hash'] else 'none'}"
              f"  ({f['n_committed']} payloads)")
        print(f"    commitment verified ...... {f['commitment_verified']}")
        print(f"    test closed cleanly ...... {f['closed']}")
    print("-" * 60)
    print("  reconstructed purely from the signed log — no live arena state used.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("export", help="path to an audit export JSON (from GET /audit/export)")
    ap.add_argument("--test-id", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    with open(args.export) as fh:
        export = json.load(fh)
    result = reconstruct(export, args.test_id)
    print(json.dumps(result, indent=2) if args.json else "", end="")
    if not args.json:
        _print(result)


if __name__ == "__main__":
    main()
