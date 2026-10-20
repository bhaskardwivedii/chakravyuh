# Threat model & residual risk (objective 06)

Chakravyuh's value depends on being honest about what it does and does not
protect. This document states the trust boundaries, the guarantees, the
conditions under which they fail, and the roadmap to close the gaps. A measured
leakage score (see `docs/RESULTS.md`) accompanies these claims.

## Assets to protect
1. **Red-team attack payloads** — must be hidden from the blue team until a test
   concludes, and red must not be able to alter them mid-test.
2. **Blue-team defensive logic / classifier weights** — must not be observable
   or inferable by red tooling.
3. **The client LLM's cleanliness** — no cross-test or cross-session
   contamination of its context.
4. **The integrity of safety findings** — a finding must be independently
   reconstructable and tamper-evident.

## Adversaries considered
- **A1 — Curious/malicious red lane**: tries to read blue logic or the model's
  internal state, or to change its payloads after seeing blue's behaviour.
- **A2 — Curious/malicious blue lane**: tries to read the red payload corpus
  early to over-fit its defence.
- **A3 — A compromised lane process**: attempts container escape, cross-lane
  network access, or secret exfiltration.
- **A4 — A party editing logs after the fact** to hide or fabricate a finding.

## What Chakravyuh protects against (enforced + measured)
| Threat | Control | Evidence |
|--------|---------|----------|
| A1 reads blue files/logic | per-lane networks + default-deny broker; no red→blue route | canary network+fs probes = 0 leaks |
| A2 reads red payloads early | commit-reveal: only a hash is shared until close | `tests/test_commit_reveal.py`, `/reveal` verify |
| A1 alters payloads mid-test | commitment binds the corpus; altered reveal rejected | e2e `test_tampered_reveal_rejected` |
| Cross-test model contamination | fresh session id per `/test/open`; lane keeps no context | `lanes/model/server.py` |
| A3 cross-lane network access | internal networks, nftables default-deny semantics | canary network probe = unreachable |
| A3 secret theft via shared mount | per-lane secret volumes | canary fs probe = not readable |
| A3 namespace escape | seccomp denies `unshare`/`setns`/`mount`; `cap_drop ALL`; no-new-privileges | verified `unshare` → EPERM |
| A4 log tampering | hash chain + signed Merkle root | `tests/test_audit.py`, tamper test |
| Noisy-neighbour timing skew | cgroup cpu/mem/pids limits + latency padding | `broker/padding.py` |

## What it does NOT protect against (residual risk)
- **Shared host kernel / runtime exploits.** All containers share one kernel. A
  0-day in the kernel or container runtime (runc/containerd) defeats the
  isolation. We reduce but do not remove this: seccomp cuts the syscall attack
  surface and caps are dropped.
- **Microarchitectural side channels** (cache, speculative execution, DRAM) on
  shared CPUs. Latency padding blunts *wall-clock* timing inference but not a
  determined microarchitectural attacker.
- **Shared-GPU memory side channels.** When a real model shares a GPU, GPU
  memory/timing channels are out of scope for the container layer.
- **A malicious cloud operator or host root.** Anyone with root on the host, or
  the cloud provider, is outside the trust boundary and can read everything.
- **Out-of-band collusion.** If red and blue collude through a channel outside
  the broker, protocol guarantees do not apply.

## Conditions under which guarantees fail
- The host kernel and container runtime are unpatched, or seccomp/AppArmor is
  disabled by the operator.
- The seccomp profile or network policy is modified from what ships here.
- A real model is served on a shared GPU without GPU-level partitioning.
- Tokens' signing secret (`BROKER_SECRET`) is weak or leaked.

## Roadmap to close the gaps
1. **Stronger runtime boundaries** — gVisor, Kata Containers or Firecracker
   microVMs per lane (a drop-in `runtimeClassName` change on Kubernetes).
2. **Confidential computing** — attested lanes on AMD SEV-SNP / Intel TDX, with
   the attestation report embedded in the audit record.
3. **Dedicated inference isolation** — one GPU (or MIG slice) per lane, or
   CPU-only models, to remove GPU side channels.
4. **Formally specified policy** — express the broker policy in Rego and prove
   properties (e.g. "no red→blue path exists in any phase").
5. **Hardware-rooted provenance** — anchor the signed Merkle root to a public
   testnet so even host root cannot rewrite history undetected.

## Trust boundary diagram
```
          ┌─────────────────────── host kernel (SHARED — residual risk) ───────────────────────┐
          │                                                                                     │
  net-red │  ┌─────────┐        net-public          ┌─────────┐  net-blue   ┌─────────┐         │
 ─────────┼─▶│  RED    │                            │  BLUE   │◀────────────│ BROKER  │         │
          │  │ (rootless│   ┌─────────┐              │(rootless│             │ default-│         │
          │  │ seccomp)│   │ operator│──────────────│ seccomp)│             │  deny   │         │
          │  └────┬────┘   │ /dash   │              └─────────┘             │ policy  │         │
          │       │        └─────────┘                                      │ +audit  │         │
          │       │                                 ┌─────────┐  net-model  │ +padding│         │
          │       └────────────── only path ───────▶│  MODEL  │◀────────────│         │         │
          │                 (broker bridges all)    │ephemeral│             └─────────┘         │
          │                                          └─────────┘                                │
          └─────────────────────────────────────────────────────────────────────────────────── ┘
   red has NO route to blue or model; every cross-lane hop goes through the broker and is audited.
```
