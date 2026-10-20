#!/usr/bin/env bash
# Canary leakage benchmark: run the SAME insider-probe suite against the
# hardened arena and against the insecure baseline, and print the leak counts
# side by side. This is the "isolation you can measure" result.
set -euo pipefail
cd "$(dirname "$0")/.."
export BASE="${BASE:-python:3.12-slim}"

run_probe() { # $1 = compose file
  docker compose -f "$1" down -v >/dev/null 2>&1 || true
  docker compose -f "$1" up -d broker model blue >/dev/null 2>&1
  # wait for lanes to write their canaries
  for _ in $(seq 1 20); do
    st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
          "$(docker compose -f "$1" ps -q broker)" 2>/dev/null || echo "")
    [ "$st" = "healthy" ] && break; sleep 2
  done
  sleep 2
  out=$(docker compose -f "$1" --profile probe run --rm probe-red 2>/dev/null | tail -1)
  docker compose -f "$1" down -v >/dev/null 2>&1 || true
  echo "$out"
}

echo "Building ..."; docker compose build --build-arg BASE="$BASE" >/dev/null

echo "Running probe against HARDENED arena ..."
HARD=$(run_probe docker-compose.yml)
echo "Running probe against INSECURE baseline ..."
INSEC=$(run_probe docker-compose.insecure.yml)

PYTHONPATH="$PWD" python3 - "$HARD" "$INSEC" <<'PY'
import sys, ast
hard = ast.literal_eval(sys.argv[1]); insec = ast.literal_eval(sys.argv[2])
def summary(d):
    chans=[f"{f['channel']}->{f['target']}" for f in d['findings'] if f['leaked']]
    return d['leaks_found'], d['probes_run'], chans
hl,hp,hc = summary(hard); il,ip,ic = summary(insec)
print("\n================= CANARY LEAKAGE BENCHMARK =================")
print(f"{'setup':<22}{'probes':>8}{'leaks':>8}   leaking channels")
print("-"*58)
print(f"{'insecure baseline':<22}{ip:>8}{il:>8}   {', '.join(ic) or '-'}")
print(f"{'Chakravyuh hardened':<22}{hp:>8}{hl:>8}   {', '.join(hc) or 'none'}")
print("-"*58)
print(f"result: hardening eliminated {il-hl} of {il} measured leaks "
      f"({'100%' if il and hl==0 else f'{round(100*(il-hl)/il) if il else 0}%'})")
print("target: 0 leaked canaries in the hardened arena  -> "
      f"{'MET' if hl==0 else 'NOT MET'}")
PY
