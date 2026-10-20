# Single image for all lanes + broker. The service is selected by the compose
# `command`. Judges build on python:3.12-slim (default); our CI/offline runs
# pass --build-arg BASE=chakravyuh-base:local to use a locally-built base when
# Docker Hub is unreachable. Behaviour is identical.
ARG BASE=python:3.12-slim
FROM ${BASE}

# ---- non-root user (defense in depth; pairs with rootless runtime) --------- #
# UID/GID 10001 owns nothing on the host. Combined with cap_drop ALL and
# no-new-privileges this makes in-container privilege escalation hard.
RUN (getent group arena || groupadd -g 10001 arena) \
 && (id arena 2>/dev/null || useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin arena) || true

WORKDIR /app

# Dependencies. (On chakravyuh-base:local these are already present; the install
# is a fast no-op there.)
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt || true

# Application code
COPY common/ /app/common/
COPY broker/ /app/broker/
COPY lanes/ /app/lanes/
COPY probes/ /app/probes/
COPY dashboard/ /app/dashboard/
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Writable mount points owned by the non-root UID. A fresh named volume mounted
# here inherits this ownership, so the broker (audit db) and lanes (canary
# secret) can write while the rest of the filesystem stays read-only.
RUN mkdir -p /data /secrets && chown -R 10001:10001 /data /secrets

# Everything else is read-only at runtime (compose sets read_only: true).
USER 10001:10001
ENTRYPOINT ["/app/entrypoint.sh"]
