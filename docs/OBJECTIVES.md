# Mapping to the Track 04 brief

Chakravyuh is built directly against Bayora's six evaluation objectives and
seven recommended technical verticals. This file is the index a judge can use to
find where each requirement is satisfied in the code.

## Evaluation objectives

| # | Objective | How Chakravyuh meets it | Where |
|---|-----------|-------------------------|-------|
| 01 | **Isolate without breaking function** | Each lane runs in its own rootless container on its own internal network; the broker preserves real-time request/response so tests still run. Latency is quantized (not inflated unboundedly) so evaluation validity is kept. | `docker-compose.yml`, `broker/app.py`, `broker/padding.py` |
| 02 | **Prevent information leakage** | Commit-reveal hides red payloads from blue until close; micro-segmentation + default-deny policy stop direct cross-lane access; per-tenant fresh sessions and latency padding address indirect/timing channels; the canary suite *measures* residual leakage (0 hardened vs 4 baseline) and the timing experiment *measures* the padding's effect. | `common/commit_reveal.py`, `broker/policy/`, `probes/canary.py`, `probes/timing_channel.py` |
| 03 | **Guarantee audit integrity** | Hash-chained append-only log sealed with an Ed25519-signed Merkle root; an independent verifier re-derives every hash and checks the signature. Tamper/reorder/deletion all detected. Each run also emits a separately signed isolation report. | `common/audit.py`, `common/report.py`, `tests/test_audit.py` |
| 04 | **Build for deployability** | Standard Docker/Podman + a plain seccomp JSON profile + public datasets. No proprietary hardware. One-command `scripts/demo.sh`. | `docker/`, `scripts/` |
| 05 | **Address LLM-native threats** | Ephemeral per-test model sessions (no shared KV cache / context carry-over); fixed-latency padding against KV-cache timing inference (cf. PromptPeek) with a *measured* ~80% reduction in a timing-channel signal; model-output isolation (only a verdict leaves the blue lane). | `lanes/model/server.py`, `broker/padding.py`, `probes/timing_channel.py` |
| 06 | **Quantify residual risk** | A written threat model stating what is and is not protected, failure conditions, and next steps — plus *measured* scores (canary leakage, timing-channel accuracy, escape-primitive checks) rather than assertions. | `docs/THREAT_MODEL.md`, `probes/`, `scripts/verify_isolation.sh` |

## Recommended technical verticals

| # | Vertical | Implementation |
|---|----------|----------------|
| 1 | Container & sandbox isolation | Rootless UID 10001, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, cgroup pids/cpu/mem limits, custom seccomp allowlist. (`docker-compose.yml`, `docker/seccomp/`) |
| 2 | Network segmentation & traffic control | Three `internal: true` networks, one per lane; the broker is the only bridge; no lane-to-lane route exists. (`docker-compose.yml`) |
| 3 | Access control & secrets management | Capability tokens (HMAC-signed, per-lane, TTL-bound) + attribute-based default-deny policy; per-lane secret volumes. (`broker/tokens.py`, `broker/policy/`) |
| 4 | Audit trails & forensic provenance | See objective 03. Optional external anchoring field for a public testnet. (`common/audit.py`) |
| 5 | Resource governance & fairness | `pids_limit`, `cpus`, `mem_limit`, `tmpfs` caps per lane; latency padding removes timing-based unfairness. (`docker-compose.yml`, `broker/padding.py`) |
| 6 | LLM-specific threat surface | Ephemeral sessions, output isolation, timing padding; see objective 05. |
| 7 | Observability & anomaly detection without leaking | The dashboard and event feed expose **metadata only** (phase, counts, policy denials, leak score) and never payload content; alerts are released only after test close. (`broker/app.py`, `dashboard/page.py`) |
