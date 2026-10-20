# 2-minute demo script

For the pitch / finale. Run `bash scripts/demo.sh` in one terminal and narrate.

**0:00 — The problem (10s).**
"Bayora tests AI models with a red team and a blue team sharing one Docker
sandbox. If they can see each other, the safety results are worthless. We seal
them apart — and we prove it."

**0:10 — Boot the arena (20s).** `scripts/demo.sh` builds and starts three lanes.
"Red, blue and the model each run in their own locked-down container on their
own network. The only thing that can talk between them is the broker."
Open `http://localhost:8000/` — the live isolation dashboard.

**0:30 — Run a real test (40s).** The red agent commits its payloads (only a
hash goes to the broker — point at the dashboard event feed), fires six attacks
through the broker, and the blue guard scores each one. Watch the verdict and
latency-pad counters move. "Blue never saw the payload list — just one prompt at
a time. The model got a fresh session, so nothing from a previous test leaks in."

**1:10 — Prove the audit trail (20s).** "Every event is hash-chained and signed."
Show the terminal line: `audit: valid=True records=22 merkle_ok=True signature_ok=True`.
"Change one logged verdict and verification fails — findings can't be forged."

**1:30 — The headline: measure the isolation (25s).** Run `scripts/benchmark.sh`.
"We plant secret canaries in each lane and attack from the inside. On the old
shared sandbox: four leaks. On Chakravyuh: zero." Point at the MET line.

**1:55 — Honesty (5s).** "And we tell you exactly what we don't protect against —
shared-kernel and microarchitectural attacks — with a written threat model and a
roadmap. That's objective six, measured, not hand-waved."

---

### If asked "is this real or mocked?"
- The isolation, networking, seccomp, commit-reveal, audit and canary results are
  **real and reproducible** — run the scripts.
- The *model* is a deterministic mock by default so it runs with no GPU; set
  `OLLAMA_URL` to swap in a real small model. The security machinery is identical
  either way.
- Every performance number in the deck (zero-canary target, <50 ms padding) is a
  **measured result or a labelled target**, never invented.
