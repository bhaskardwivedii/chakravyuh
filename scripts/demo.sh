#!/usr/bin/env bash
# Chakravyuh one-command demo: build, boot the hardened arena, run a full
# red/blue/model test through the broker, seal + verify the audit trail, and
# print the dashboard URL. ~2 minutes. Target for the live hackathon demo.
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

echo "▶ Sealing and verifying the audit trail ..."
OP=$(curl -s http://localhost:8000/token/operator | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s -XPOST http://localhost:8000/seal -H "x-token: $OP" >/dev/null
curl -s http://localhost:8000/audit/export > /tmp/chakravyuh_export.json
PYTHONPATH="$PWD" python3 - <<'PY'
import json; from common.audit import verify_chain
r=verify_chain(json.load(open('/tmp/chakravyuh_export.json')))
print(f"   audit: valid={r['valid']} records={r['records_checked']} "
      f"merkle_ok={r['merkle_root_ok']} signature_ok={r['signature_ok']}")
PY

echo "▶ Done. Leave it running to explore the dashboard, or: docker compose down -v"
