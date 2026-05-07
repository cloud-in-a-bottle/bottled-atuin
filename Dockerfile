# Atuin shell-history sync server packaged for OpenHost.
#
# Layout:
#
#   /opt/openhost-atuin/
#     start.sh         — supervises atuin-server + auth-proxy
#     auth_proxy.py    — owner-gate sidecar (defense in depth)
#
# Auth flow:
#
#   * /register   → only reachable by the zone owner (the OpenHost
#                   router gates non-public paths on owner JWT).
#                   This is how we keep the server single-tenant.
#   * everything  → CLI clients (atuin) hit these with their own
#     else          `Authorization: Token <token>` header.  The
#                   auth-proxy strips OpenHost trust headers but
#                   otherwise forwards untouched.
#
# We download the prebuilt atuin-server binary at image-build time
# rather than `cargo build` from source — keeps the build fast and
# the image small (~25 MiB).

FROM debian:bookworm-slim

ARG ATUIN_VERSION=v18.16.0
ARG TARGETARCH

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        tini \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
        amd64) ARCH="x86_64-unknown-linux-gnu" ;; \
        arm64) ARCH="aarch64-unknown-linux-gnu" ;; \
        *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/atuinsh/atuin/releases/download/${ATUIN_VERSION}/atuin-server-${ARCH}.tar.gz" \
        -o /tmp/atuin-server.tgz; \
    tar -C /tmp -xzf /tmp/atuin-server.tgz; \
    install -m 0755 /tmp/atuin-server-${ARCH}/atuin-server /usr/local/bin/atuin-server; \
    rm -rf /tmp/atuin-server.tgz /tmp/atuin-server-${ARCH}; \
    /usr/local/bin/atuin-server --version

COPY start.sh        /opt/openhost-atuin/start.sh
COPY auth_proxy.py   /opt/openhost-atuin/auth_proxy.py

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-atuin/start.sh"]
