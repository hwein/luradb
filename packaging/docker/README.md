# Try LuraDB with Docker

Run LuraDB in a container built from a `.deb` package you provide — no Rust
toolchain, no package install on the host.

> This is a local dev/try image for exploring LuraDB, not a production
> distribution image — nothing here is meant to be pushed to a registry or
> handed to someone else. The admin key (see below) is generated fresh on
> your own machine at container start, not baked into the image.

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
   Auth is on by default too, so the UI needs a Bearer key before it can load
   its own `/api-docs/openapi.json` — open its "Authorize" button and paste
   the admin key from the next section.

## Admin key

The container generates a fresh admin key on its **first** start only, and
prints it once to the log:

```sh
docker compose logs luradb | grep "admin api key"
```

From then on the key lives in the `etc` volume (`/etc/luradb/luradb.toml`) —
later starts reuse it instead of generating a new one. If you missed the log
line, read it back from there instead:

```sh
docker compose exec luradb grep api_key /etc/luradb/luradb.toml
```

The key starts with `lura_`. Use it for the first authenticated request:

```sh
curl -H "Authorization: Bearer <key>" http://localhost:3000/version
```

To use your own key instead of a generated one, set `LURADB_ADMIN_KEY` in
the container's environment before the first start. The stock `compose.yaml`
doesn't forward host variables into the container, so this needs a `docker
run`/`docker compose run -e` invocation, or your own `environment:` entry.

## Why compose

Docker's default seccomp profile blocks the io_uring syscalls LuraDB
requires; `compose.yaml` carries the exemption (`security_opt:
seccomp=unconfined`). A bare `docker run` without that option fails at
startup.
