# Hack in Hills '26 — Round 2 submission

**Team Chakravyuh** · Track 04 — Securing Adversarial AI Safety Testing
Infrastructure (Bayora)
Hosted by BuilderBase × Nexido × Web3 India · Grand Finale: Manali, 20–21 Nov 2026

---

## Round 2A — Prototype Development (18–24 Oct 2026)

Official requirements and where each is met:

| Requirement | Status | Where |
|-------------|:------:|-------|
| Build a functional prototype / MVP | ✅ | `bash scripts/demo.sh` runs the full arena end-to-end |
| Demonstrate the core solution | ✅ | Red→broker→model→blue test + signed audit verification |
| Maintain a GitHub repository | ✅ | this repository |
| Show technical feasibility and usability | ✅ | 31 passing tests + live dashboard at `http://localhost:8000/` |
| Prepare a short demo video | ⏳ **you record this** | script in [`docs/DEMO.md`](docs/DEMO.md) |

## Round 2B — Social Pitch & Outreach (24–27 Oct 2026)
Final submission deadline: **27 Oct 2026, 11:59 PM IST**, via the Round 2 form.

- [ ] LinkedIn post presenting the idea, solution and what makes it unique — tag **Eren, Builder Base, Nexido, Web3 India**
- [ ] Instagram Reel on why the team is building this — tag **Eren.dev, Builder Base, Nexido, Web3 India**
- [ ] Short prototype demo video + this GitHub link
- [ ] Submit all links through the designated Round 2 form

## Final evaluation (28–29 Oct) — criteria mapping

| Criterion | Where it shows |
|-----------|----------------|
| Innovation | Measured isolation via canary probes; commit-reveal red/blue protocol; non-leaking audit layer |
| Problem–solution fit | All 6 objectives + 7 verticals mapped in [`docs/OBJECTIVES.md`](docs/OBJECTIVES.md) |
| Functional implementation | Real containers, real crypto, 31 tests — [`docs/RESULTS.md`](docs/RESULTS.md) |
| Technical execution | 5-layer architecture, 252-syscall seccomp profile, Ed25519-sealed audit log |
| Impact | Makes safety findings trustworthy and independently reproducible |
| Usability | One-command demo + live metadata-only dashboard |
| Presentation | 2-minute demo script in [`docs/DEMO.md`](docs/DEMO.md) |

---

## How a judge verifies it in 3 commands

```bash
PYTHONPATH=. pytest -q      # 31 passing tests
bash scripts/demo.sh        # full test run + signed audit verification + dashboard
bash scripts/benchmark.sh   # canary leakage: 0 (hardened) vs 4 (insecure baseline)
```

Runs on `python:3.12-slim` — no GPU, no model download, no proprietary hardware.

## Honesty notes (please read before the demo)

- The **client LLM is a deterministic mock by default** so the arena runs
  anywhere; the isolation, networking, seccomp, commit-reveal, audit and canary
  machinery around it is fully real. Set `OLLAMA_URL` to swap in a real small
  model — the security layer is unchanged.
- Every number in the deck and docs is either a **measured result**
  (`docs/RESULTS.md`) or a **clearly labelled target**.
- This is a hackathon proof of concept. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
  states exactly what it does and does not protect against (objective 06).

## AI assistance

AI coding assistants were used while building this project — explicitly allowed
and encouraged by Hack in Hills '26 (the event runs its own TinyFish AI-agent
challenge). The architecture, security model and design decisions are the team's
own and are documented in `docs/`.

> **Optional — TinyFish Builder Challenge:** separate and optional. If you take
> it up, the natural fit is a web agent that pulls public adversarial-prompt
> datasets (JailbreakBench / AdvBench) into the red lane's `PAYLOAD_FILE`. Form:
> https://forms.gle/TCW5jukdGB6bnRm19
