# Try LuraDB with Docker

Run LuraDB in a container built from a `.deb` package you provide — no Rust
toolchain, no package install on the host.

## Prerequisites

- Docker with Linux containers (Docker Engine on Linux, or Docker Desktop on
  Windows/macOS/Linux).
- git.

## Quickstart

1. Clone the repo:

   ```sh
   git clone https://github.com/hwein/luradb.git
   ```

2. Download the latest `luradb_*.deb` from the
   [Releases page](https://github.com/hwein/luradb/releases) and drop it
   into the cloned repo under `target/debian/`:

   ```sh
   mkdir -p luradb/target/debian
   ```

   Building it yourself works too — `cargo deb` places the package there
   automatically (toolchain setup: main README, "Build from source").

3. Build the image and start the container:

   ```sh
   cd luradb/packaging/docker
   docker compose up -d
   ```

   The build installs the package like a real target system — nothing is
   compiled, and nothing beyond the `ubuntu:24.04` base image is pulled
   from a registry.

4. Once the container is `healthy`:

   ```sh
   curl http://localhost:3000/health
   ```

   The Swagger UI is enabled in this setup: <http://localhost:3000/test-ui>.

## Admin key

```sh
docker compose exec luradb grep api_key /etc/luradb/luradb.toml
```

The key starts with `lura_`. Use it for the first authenticated request:

```sh
curl -H "Authorization: Bearer <key>" http://localhost:3000/version
```

## Why compose (io_uring)

Docker's default seccomp profile blocks the io_uring syscalls LuraDB
requires; `compose.yaml` carries the exemption (`security_opt:
seccomp=unconfined`). A bare `docker run` without that option fails at
startup.
