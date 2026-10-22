"""
Operator lane — the trusted control plane that drives a test's lifecycle.

This is deliberately SEPARATE from the red/blue tenants. In the Bayora model the
operator is the evaluation platform itself (trusted), while red and blue are
untrusted tenants. Only the operator holds the operator bootstrap key and may
open/close/seal a test; the red tenant cannot obtain operator rights (see the
gated /token endpoint and docker-compose.yml, where each container gets only its
own key).

Lifecycle (coordinating with red purely through the broker's /state):
  1. open the test  (phase -> commit)
  2. wait until red has committed and sent all its attacks
  3. close the test (phase -> closed) so red may reveal
  4. wait until red's commitment is revealed and verified
  5. seal the audit log (authenticated) — the tamper-evident checkpoint

Run as a module:  python -m lanes.operator.driver
"""
from __future__ import annotations

import json
import os
import sys
import time

import httpx

BROKER = os.environ.get("BROKER_URL", "http://broker:8000")
BOOTSTRAP_KEY = os.environ.get("BOOTSTRAP_KEY", "dev-operator-bootstrap-change-me")


def get_operator_token(client: httpx.Client) -> str:
    r = client.get(f"{BROKER}/token/operator", headers={"x-bootstrap": BOOTSTRAP_KEY})
    r.raise_for_status()
    return r.json()["token"]


def _poll(client: httpx.Client, predicate, timeout: float, what: str) -> dict:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        last = client.get(f"{BROKER}/state").json()
        if predicate(last):
            return last
        time.sleep(0.3)
    raise TimeoutError(f"timed out waiting for {what}; last state={last}")


def run() -> dict:
    with httpx.Client(timeout=60) as client:
        token = get_operator_token(client)
        H = {"x-token": token}

        # 1) open
        opened = client.post(f"{BROKER}/test/open", headers=H)
        opened.raise_for_status()
        test_id = opened.json()["test_id"]

        # 2) wait until red committed AND all committed attacks were processed
        def attacks_done(s):
            n = s.get("n_committed_payloads") or 0
            return n > 0 and s.get("attacks_processed", 0) >= n and s["phase"] == "running"
        _poll(client, attacks_done, timeout=120, what="red to finish attacking")

        # 3) close so red may reveal
        client.post(f"{BROKER}/test/close", headers=H).raise_for_status()

        # 4) wait for red's reveal to be verified
        _poll(client, lambda s: s.get("payloads_revealed") is True,
              timeout=60, what="red to reveal its corpus")

        # 5) seal the audit log (authenticated operator action)
        sealed = client.post(f"{BROKER}/seal", headers=H)
        sealed.raise_for_status()

    return {"test_id": test_id, "sealed": sealed.json()["merkle_root"][:16] + "…"}


if __name__ == "__main__":
    for _ in range(30):
        try:
            with httpx.Client(timeout=5) as c:
                if c.get(f"{BROKER}/healthz").status_code == 200:
                    break
        except Exception:
            time.sleep(1)
    out = run()
    print(json.dumps(out, indent=2))
    sys.exit(0)
