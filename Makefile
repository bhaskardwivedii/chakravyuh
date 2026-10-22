# Chakravyuh — convenience targets. BASE overrides the container base image
# (default python:3.12-slim; use chakravyuh-base:local in air-gapped CI).
BASE ?= python:3.12-slim
export BASE

.PHONY: help build demo benchmark isolation timing evaluate replay test up down clean
help:
	@echo "make build      - build the container image"
	@echo "make demo       - one-command end-to-end demo + signed scorecard (+ dashboard :8000)"
	@echo "make benchmark  - canary leakage: hardened vs insecure baseline"
	@echo "make isolation  - run escape primitives in a hardened container, confirm blocked"
	@echo "make timing     - measure the timing-channel defense (padding off vs on)"
	@echo "make evaluate   - at-scale detection metrics over the adversarial corpus"
	@echo "make replay     - reconstruct a finding from a signed audit export"
	@echo "make test       - run the pytest suite (no Docker required)"
	@echo "make up / down  - start / stop the hardened arena"
	@echo "make clean      - stop everything and remove volumes"

isolation:
	bash scripts/verify_isolation.sh

timing:
	PYTHONPATH=. python3 -m probes.timing_channel

evaluate:
	PYTHONPATH=. python3 -m probes.evaluate

replay:
	@test -f /tmp/chakravyuh_export.json || { echo "run 'make demo' first to produce an export"; exit 1; }
	PYTHONPATH=. python3 -m common.replay /tmp/chakravyuh_export.json

build:
	docker compose build --build-arg BASE=$(BASE)

demo:
	bash scripts/demo.sh

benchmark:
	bash scripts/benchmark.sh

test:
	PYTHONPATH=. pytest -q

up: build
	docker compose up -d broker model blue

down:
	docker compose down

clean:
	-docker compose down -v
	-docker compose -f docker-compose.insecure.yml down -v
