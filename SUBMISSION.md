## Honesty notes 

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

 
