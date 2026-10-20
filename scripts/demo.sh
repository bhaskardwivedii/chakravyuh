#!/usr/bin/env bash
# Chakravyuh one-command demo: build, boot the hardened arena, run a full
# red/blue/model test through the broker, seal + verify the audit trail, and
# print the dashboard URL. ~2 minutes. Suitable for a live walkthrough.
set -euo pipefail
cd "$(dirname "$0")/.."

export BASE="${BASE:-python:3.12-slim}"
COMPOSE="docker compose"

echo "▶ Building images (BASE=$BASE) ..."
$COMPOSE build --build-arg BASE="$BASE" >/dev/null

echo "▶ Starting hardened arena (broker, model, blue) ..."
$COMPOSE up -d broker model blue >/dev/null

echo -n "▶ Waiting for broker health "
for _ in $(seq 1 30); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
        "$($COMPOSE ps -q broker)" 2>/dev/null || echo "")
  [ "$st" = "healthy" ] && { echo " ✓"; break; }
  echo -n "."; sleep 2
done

echo "▶ Dashboard:  http://localhost:8000/   (metadata-only isolation view)"
echo "▶ Running red agent (commit → attack → close → reveal) ..."
$COMPOSE run --rm red

echo "▶ Running canary insider-probe (measuring cross-lane leakage) ..."
$COMPOSE --profile probe run --rm probe-red >/dev/null 2>&1 || true

echo "▶ Issuing signed isolation report + verifying the audit trail ..."
curl -s http://localhost:8000/report > /tmp/chakravyuh_report.json
curl -s http://localhost:8000/audit/export > /tmp/chakravyuh_export.json

PYTHONPATH="$PWD" python3 - <<'PY'
import json
from common.audit import verify_chain
from common.report import verify_report

audit = verify_chain(json.load(open('/tmp/chakravyuh_export.json')))
signed = json.load(open('/tmp/chakravyuh_report.json'))
rep = verify_report(signed); b = signed["report"]

def ok(x): return "OK" if x else "FAIL"
print("\n" + "=" * 52)
print("  CHAKRAVYUH — ISOLATION SCORECARD")
print("=" * 52)
print(f"  attacks processed .......... {b['attacks_processed']}")
print(f"  jailbreaks blocked ......... {b['verdicts']['blocked']}/{b['attacks_processed']}"
      f"  (block rate {b['block_rate']})")
print(f"  canary leakage ............. {b['canary_leaks']}  (target 0)")
print(f"  payloads commitment ........ {ok(b['payloads_commitment_verified'])}")
print(f"  audit trail ................ {ok(audit['valid'])}"
      f"  ({b['audit_records']} records, signed)")
print(f"  isolation report signature . {ok(rep['valid'])}")
print("=" * 52)
print(f"  report hash: {signed['report_hash'][:32]}…")
print("  (verify independently with common/report.py)")
PY

echo
echo "▶ Done. Dashboard still live at http://localhost:8000/"
echo "  More proofs:  bash scripts/benchmark.sh   (canary: hardened vs baseline)"
echo "                bash scripts/verify_isolation.sh   (escape primitives blocked)"
echo "                python3 -m probes.timing_channel   (timing-channel defense)"
echo "  Tear down:    docker compose down -v"
