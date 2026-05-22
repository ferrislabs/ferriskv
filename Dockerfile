# syntax=docker/dockerfile:1.7
#
# Multi-target image. Build with `--target node` for the server, `--target cli`
# for the client. Both targets share the dependency-compilation cache below.
#
#   docker build --target node -t ferriskv-node:latest .
#   docker build --target cli  -t ferriskv-cli:latest  .

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json \
    -p ferriskv-node -p ferriskv-cli
COPY . .
RUN cargo build --release --locked -p ferriskv-node -p ferriskv-cli

# Common base for runtime stages: small debian with ca-certs and a non-root user.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ferriskv \
    && useradd --system --uid 10001 --gid ferriskv --home-dir /var/lib/ferriskv --shell /usr/sbin/nologin ferriskv \
    && mkdir -p /var/lib/ferriskv /etc/ferriskv \
    && chown -R ferriskv:ferriskv /var/lib/ferriskv /etc/ferriskv
ENV RUST_LOG=info

# Server target: ferriskv-node.
FROM runtime-base AS node
COPY --from=builder /build/target/release/ferriskv-node /usr/local/bin/ferriskv-node
USER ferriskv:ferriskv
WORKDIR /var/lib/ferriskv
EXPOSE 7100 7101
VOLUME ["/var/lib/ferriskv"]
# No HEALTHCHECK on purpose: /healthz is exposed only when admin_listen is set
# in node.toml. Orchestrators (k8s probes, compose) should target /healthz on
# the admin port directly when enabled.
ENTRYPOINT ["/usr/local/bin/ferriskv-node"]
CMD ["--config", "/etc/ferriskv/node.toml"]

# Client target: ferriskv CLI.
FROM runtime-base AS cli
COPY --from=builder /build/target/release/ferriskv /usr/local/bin/ferriskv
USER ferriskv:ferriskv
WORKDIR /var/lib/ferriskv
ENTRYPOINT ["/usr/local/bin/ferriskv"]
CMD ["--help"]
