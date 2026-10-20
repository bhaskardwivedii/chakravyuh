#!/usr/bin/env bash
# Adversarial isolation checks: run escape/privilege primitives INSIDE a hardened
# lane container and confirm the sandbox blocks each one. This turns the
# container-hardening claims (vertical 1, objective 01) into observable PASS/FAIL
# results a judge can re-run.
#
# Each check runs with the SAME hardening the arena uses: the seccomp profile,
# cap_drop ALL, no-new-privileges, non-root user, read-only rootfs.
set -uo pipefail
cd "$(dirname "$0")/.."
export BASE="${BASE:-python:3.12-slim}"
IMG="chakravyuh:latest"
SECCOMP="$PWD/docker/seccomp/chakravyuh.json"

docker compose build >/dev/null 2>&1 || docker build -q -f docker/Dockerfile \
  --build-arg BASE="$BASE" -t "$IMG" . >/dev/null

HARDEN=(--rm
  --security-opt "seccomp=$SECCOMP"
  --security-opt no-new-privileges
  --cap-drop ALL --user 10001:10001 --read-only --tmpfs /tmp
  --network none --pids-limit 128 --memory 512m)

pass=0; fail=0
check() { # name, expect_blocked(1/0), python-snippet
  local name="$1" expect="$2" code="$3" out rc
  out=$(docker run "${HARDEN[@]}" "$IMG" python3 -c "$code" 2>&1); rc=$?
  # snippet prints BLOCKED or ALLOWED; treat a crash (seccomp kill) as BLOCKED
  if echo "$out" | grep -q BLOCKED || [ $rc -ne 0 ]; then got=blocked; else got=allowed; fi
  if { [ "$expect" = 1 ] && [ "$got" = blocked ]; } || { [ "$expect" = 0 ] && [ "$got" = allowed ]; }; then
    printf "  PASS  %-42s (%s)\n" "$name" "$got"; pass=$((pass+1))
  else
    printf "  FAIL  %-42s (%s)\n" "$name" "$got"; fail=$((fail+1))
  fi
}

echo "============================================================"
echo "ADVERSARIAL ISOLATION CHECKS (hardened lane container)"
echo "============================================================"

# 1) new mount namespace — namespace-escape primitive; seccomp should deny unshare
check "unshare(CLONE_NEWNS) denied" 1 '
import ctypes,ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library("c"),use_errno=True)
print("BLOCKED" if libc.unshare(0x00020000)!=0 else "ALLOWED")'

# 2) mount() — should be blocked by dropped CAP_SYS_ADMIN and/or seccomp
check "mount() denied" 1 '
import ctypes,ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library("c"),use_errno=True)
r=libc.mount(b"none",b"/mnt",b"tmpfs",0,0)
print("BLOCKED" if r!=0 else "ALLOWED")'

# 3) write to the read-only root filesystem
check "write to read-only rootfs denied" 1 '
try:
    open("/etc/evil","w").write("x"); print("ALLOWED")
except OSError: print("BLOCKED")'

# 4) raw socket (needs CAP_NET_RAW, which is dropped)
check "raw socket (CAP_NET_RAW) denied" 1 '
import socket
try:
    socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); print("ALLOWED")
except (PermissionError,OSError): print("BLOCKED")'

# 5) ptrace another process (process_vm/ptrace denied by seccomp)
check "ptrace denied" 1 '
import ctypes,ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library("c"),use_errno=True)
# PTRACE_ATTACH=16 to pid 1; blocked syscall -> nonzero / errno
r=libc.ptrace(16,1,0,0)
print("BLOCKED" if r!=0 else "ALLOWED")'

# 6) sanity: the lane CAN still do its real work (bind a local socket, import deps)
check "legit app syscalls still allowed" 0 '
import socket,fastapi,httpx
s=socket.socket(); s.bind(("127.0.0.1",0)); s.close()
print("ALLOWED")'

echo "------------------------------------------------------------"
echo "isolation checks: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "result: sandbox blocks all escape primitives while preserving function  -> PASS"
exit "$fail"
