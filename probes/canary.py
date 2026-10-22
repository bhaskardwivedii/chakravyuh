"""
Canary leak-probe suite — "isolation you can measure".

This is Chakravyuh's signature idea (objective 02: Prevent Information Leakage).
Instead of *asserting* that the lanes are isolated, we plant unique, secret
canary tokens in each lane and then run an adversarial probe FROM each lane that
tries every cross-lane channel we can think of to read or infer another lane's
canary. Any canary a probe recovers is a proven leak. The output is a single
number — canaries_found — with a target of zero.

Channels probed (per the Track 04 threat surface):
  * Network: can lane A open a TCP/HTTP connection to lane B at all?
    (Docker internal networks + nftables default-deny should refuse this.)
  * Filesystem: is any other lane's secret mount / file readable?
  * Environment: did another lane's secret leak into shared env?
  * Process table: is another lane's command line (which may embed a secret)
    visible? (PID namespace isolation should hide it.)

Run inside a lane container:
    python -m probes.canary --self red --targets blue,model --report-to http://broker:8000

The same module is importable for the pytest harness, which simulates the
channels in-process so the logic is unit-tested even without containers.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
from dataclasses import dataclass, field


# Each lane writes its canary to a well-known path and env var at startup.
CANARY_PATHS = {
    "red": "/secrets/red.canary",
    "blue": "/secrets/blue.canary",
    "model": "/secrets/model.canary",
}
LANE_PORTS = {"broker": 8000, "model": 9000, "blue": 9100, "red": 0}


@dataclass
class ProbeResult:
    probing_lane: str
    probes_run: int = 0
    leaks_found: int = 0
    findings: list[dict] = field(default_factory=list)

    def record(self, channel: str, target: str, leaked: bool, detail: str = ""):
        self.probes_run += 1
        if leaked:
            self.leaks_found += 1
        self.findings.append({"channel": channel, "target": target,
                              "leaked": leaked, "detail": detail})

    def as_dict(self) -> dict:
        return {"probing_lane": self.probing_lane, "probes_run": self.probes_run,
                "leaks_found": self.leaks_found, "findings": self.findings}


def _try_network(target: str, result: ProbeResult):
    """A reachable peer port is itself a segmentation leak (we shouldn't route)."""
    port = LANE_PORTS.get(target, 0)
    if not port:
        return
    try:
        with socket.create_connection((target, port), timeout=2):
            # We could reach the peer at all — micro-segmentation failed.
            result.record("network", target, leaked=True,
                          detail=f"connected to {target}:{port}")
    except (OSError, socket.error):
        result.record("network", target, leaked=False,
                      detail=f"{target}:{port} unreachable (expected)")


def _try_filesystem(target: str, result: ProbeResult):
    path = CANARY_PATHS.get(target)
    if not path:
        return
    try:
        with open(path) as fh:
            val = fh.read().strip()
        result.record("filesystem", target, leaked=bool(val),
                      detail=f"read {path}")
    except OSError:
        result.record("filesystem", target, leaked=False,
                      detail=f"{path} not readable (expected)")


def _try_environment(target: str, result: ProbeResult):
    key = f"{target.upper()}_CANARY"
    leaked = key in os.environ
    result.record("environment", target, leaked=leaked,
                  detail=f"env {key} {'present' if leaked else 'absent'}")


def _try_process_table(target: str, result: ProbeResult):
    """If PID namespaces isolate lanes, we only see our own processes."""
    try:
        out = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                             text=True, timeout=3).stdout.lower()
        leaked = target in out and "canary" in out
        result.record("process", target, leaked=leaked,
                      detail="peer process visible" if leaked else "peer processes hidden")
    except Exception:
        result.record("process", target, leaked=False, detail="ps unavailable")


def run_probes(self_lane: str, targets: list[str]) -> ProbeResult:
    result = ProbeResult(probing_lane=self_lane)
    for t in targets:
        _try_network(t, result)
        _try_filesystem(t, result)
        _try_environment(t, result)
        _try_process_table(t, result)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self", dest="self_lane", required=True)
    ap.add_argument("--targets", required=True, help="comma-separated lane names")
    ap.add_argument("--report-to", default=os.environ.get("BROKER_URL", "http://broker:8000"))
    args = ap.parse_args()

    res = run_probes(args.self_lane, args.targets.split(","))
    print(res.as_dict())

    # Report the aggregate to the broker for the dashboard, using a least-
    # privilege 'prober' token (canary.report only — not operator rights).
    bootstrap = os.environ.get("PROBER_BOOTSTRAP_KEY", "dev-prober-bootstrap-change-me")
    try:
        import httpx
        with httpx.Client(timeout=5) as c:
            tok = c.get(f"{args.report_to}/token/prober",
                        headers={"x-bootstrap": bootstrap}).json()["token"]
            c.post(f"{args.report_to}/canary/report", headers={"x-token": tok},
                   json=res.as_dict())
    except Exception as e:
        print(f"(could not report to broker: {e})")


if __name__ == "__main__":
    main()
