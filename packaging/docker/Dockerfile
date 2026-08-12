# --- Stage 1: build the .deb entirely inside the container ---
FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential dpkg-dev
# Toolchain pinned by rust-toolchain.toml (same pattern as release.yml).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
COPY . .
RUN rustup show && cargo install --locked cargo-deb && cargo deb

# --- Stage 2: install the .deb like a real target system ---
FROM ubuntu:24.04
COPY --from=builder /src/target/debian/luradb_*.deb /tmp/luradb.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl /tmp/luradb.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/luradb.deb
# Docker port mapping reaches the container via its network interface only;
# the host-side bind stays local (compose.yaml publishes 127.0.0.1 only).
RUN sed -i 's/^bind_address = "127.0.0.1"$/bind_address = "0.0.0.0"/' /etc/luradb/luradb.toml
COPY packaging/docker/entrypoint.sh /usr/local/bin/luradb-entrypoint
RUN chmod +x /usr/local/bin/luradb-entrypoint
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/luradb-entrypoint"]
