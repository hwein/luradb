# Try LuraDB with Docker

Build and run LuraDB from this repo with nothing but Docker and git installed
— no Rust toolchain, no manual package install. The image is built locally;
nothing is pulled from a registry.

## Prerequisites

- Docker with Linux containers (Docker Engine on Linux, or Docker Desktop on
  Windows/macOS/Linux). No Rust toolchain needed — the build happens inside
  the container.
- git.

## Quickstart

```sh
git clone https://github.com/hwein/luradb.git
cd luradb/packaging/docker
docker compose up -d
```

The first run builds the image from the cloned sources: a builder stage
compiles LuraDB and packages the .deb entirely inside the container, a
second stage then installs that .deb like a real target system — nothing
is downloaded from a registry and no prebuilt package is required. This
takes a few minutes; later runs reuse the Docker layer cache. Once the
container is `healthy`:

```sh
curl http://localhost:3000/health
```

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

## Customizing

- **Change the port:** set `LURADB_PORT` before starting, e.g.
  `LURADB_PORT=8080 docker compose up -d`.
- **Enable the Swagger UI:**
  ```sh
  docker compose exec luradb sed -i 's/^swagger_enabled = false/swagger_enabled = true/' /etc/luradb/luradb.toml
  docker compose restart
  ```
- **Adjust the config generally:** same route — `exec` in an edit, then
  `docker compose restart`. The config lives in the `etc` volume, not the
  image, so changes survive container recreation.
- **Make it reachable from outside the host:** change the `ports:` line in
  `compose.yaml` from `127.0.0.1:${LURADB_PORT:-3000}:3000` to a binding
  that isn't localhost-only. Only do this on a trusted network — the
  container has no TLS in this setup, and anyone who can reach the port can
  reach the API with only the admin key as a barrier.

## Data & lifecycle

- **Stop / start:** `docker compose stop` / `docker compose start`.
- **Logs:** `docker compose logs -f`.
- **Update to a new repo state:** `git pull` then `docker compose up -d --build`
  — data and the admin key are kept (they live in named volumes, not the
  image).
- **Full reset:** `docker compose down -v` — drops both volumes; the next
  `up -d` starts with an empty store. The admin key reverts to the one baked
  into the image at build time; for a brand-new key, rebuild without cache
  (`docker compose build --no-cache`).
- **Clean up entirely:** `docker compose down -v`, then
  `docker image rm luradb:local`.
