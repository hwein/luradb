<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/luradb-wordmark.svg">
  <img src=".github/luradb-wordmark-light.svg" alt="LuraDB" height="40">
</picture>

#

LuraDB is a Linux-first, REST-native multi-model database built on io_uring.
One small, fast process covers the three shapes of data a typical backend
needs: a key-value store (TTLs, watches), JSON documents (indexes, queries),
and slim relational tables (views, left joins). Its interface is a RESTful
API — no proprietary protocol, no driver stack to install: every language
and standard tool can talk to it out of the box, and the API is browsable
down to the individual record.

**Built for the small jobs, done well.**

## Where LuraDB lives

- **Your own service** — A backend that ships with your service: one
  package, one unit, a REST API it talks to directly.
  <img src=".github/tag-rel.svg" alt="REL" height="18"> <img src=".github/tag-json.svg" alt="JSON" height="18"> <img src=".github/tag-kv.svg" alt="KV" height="18">
- **Sessions that clean up after themselves** — Sessions and tokens with a
  TTL expire on their own. No Redis on the side.
  <img src=".github/tag-kv.svg" alt="KV" height="18">
- **Memory for your agents** — Give AI agents a real store over MCP: keys
  for state, documents for context, tables for facts.
  <img src=".github/tag-rel.svg" alt="REL" height="18"> <img src=".github/tag-json.svg" alt="JSON" height="18"> <img src=".github/tag-kv.svg" alt="KV" height="18">
- **Flags that flip live** — Services watch a key and switch the moment it
  changes. No redeploy, no polling.
  <img src=".github/tag-kv.svg" alt="KV" height="18">
- **Catalogs with loose ends** — Fixed fields in a table, the messy
  attributes in JSON, linked in one row.
  <img src=".github/tag-rel.svg" alt="REL" height="18"> <img src=".github/tag-json.svg" alt="JSON" height="18">
- **One customer, one domain** — Each tenant gets its own domain, its own
  API keys, its own permissions.
  <img src=".github/tag-rel.svg" alt="REL" height="18"> <img src=".github/tag-json.svg" alt="JSON" height="18"> <img src=".github/tag-kv.svg" alt="KV" height="18">
- **The webhook inbox** — Catch every incoming payload as it is. Index it,
  search it later.
  <img src=".github/tag-json.svg" alt="JSON" height="18">
- **Throwaway database for pipelines** — A real, persistent store for CI
  runs, installers and playbooks. Seeded, used, gone.
  <img src=".github/tag-json.svg" alt="JSON" height="18"> <img src=".github/tag-kv.svg" alt="KV" height="18">
- **On the host, out of the way** — Sidecar over a Unix socket, installed
  in one step, under systemd, logging to journald.
  <img src=".github/tag-rel.svg" alt="REL" height="18"> <img src=".github/tag-json.svg" alt="JSON" height="18"> <img src=".github/tag-kv.svg" alt="KV" height="18">

**What LuraDB is not.** LuraDB does not aim to be Oracle, PostgreSQL or
MySQL — nor MongoDB, Cassandra or Spark. There is no analytical engine, no
distributed cluster, no data-warehouse ambition: if your project needs a
Data Vault, you have outgrown LuraDB — and that is by design. Features earn
their place by making the small case better, not by making LuraDB bigger.

**Why "Lura"?** **L**inux + io_**ur**ing + **a**sync — the letters the
architecture is built on.

LuraDB is your friendly neighborhood database.

## Try it in two minutes

- **Docker, any OS:** drop a `.deb` from the
  [Releases](https://github.com/hwein/luradb/releases) into
  `target/debian/`, run `docker compose up -d` —
  [packaging/docker](packaging/docker/README.md).
- **Linux host:** `sudo apt install ./luradb_*.deb`, start the service,
  done — [Install](#install).
- **Curl it:** `curl http://127.0.0.1:3000/health` — then the
  [Quick tour](#quick-tour).

## Features

- **Key-value:** keys with TTL, prefix listings and counts, bulk delete, a
  resumable watch stream (SSE), and conditional writes: every key carries an
  `ETag`, writes accept `If-Match` and `If-None-Match: *`, and a domain can
  require them.
- **JSON documents:** versioned documents with `ETag` and conditional
  writes, secondary indexes, search queries, NDJSON bulk load.
- **Slim relational (LuraSQL):** tables, indexes, views and left joins over
  `/sql` and row endpoints, CSV/TSV import with inferred column types, and
  KVREF/JSONREF columns that link rows to keys and documents.
- **One API for all three:** domains, API keys with per-domain permissions,
  a resumable stream of lifecycle and DDL events, metrics and health,
  logical backups with schedules, retention and restore.
- **Access paths:** HTTP, native HTTPS, a Unix domain socket for local
  clients, CORS for browser clients, and a built-in MCP server for AI
  assistants.
- **Durability:** a write is confirmed only once it is in the write-ahead
  log (group commit across engines, segments cleaned without a write
  pause); a failed fsync or repeated data-file write errors stop the
  service so the next start recovers from the log instead of serving data
  it may have lost.
- **Operations:** one binary, a `.deb` with systemd service, journald
  logging, multicore data shards, and a watch on disk space and memory that
  refuses writes before the host runs dry.

## Status

LuraDB is `0.x`, pre-1.0 software. On-disk formats and the REST API can
change between minor releases. See [CHANGELOG.md](CHANGELOG.md) for what
changed in each release — entries touching the REST API are marked `API:`,
breaking changes are marked **BREAKING**.

0.5.0 changes the on-disk format: the write-ahead log becomes a directory
of segments, engine files move into a shard directory, and users, API key
hashes and permissions move into a separate system store. A data directory
written by 0.4.0 is upgraded automatically on the first start — one way.
Going back to 0.4.0 needs a backup taken before the upgrade, restored into
the older version.

## Requirements

- Linux, amd64.
- Linux kernel 6.1 or newer (io_uring with `DEFER_TASKRUN`); LuraDB refuses
  to start on older kernels.
- systemd, if you install the `.deb` package (LuraDB runs as a systemd
  service).

## Install

Download the latest `.deb` from the newest [GitHub
Release](https://github.com/hwein/luradb/releases) and install it:

```sh
sudo apt install ./luradb_*.deb
```

`apt` resolves the runtime dependencies, creates the `luradb` system user,
generates an admin API key and enables the systemd service without
starting it, so you can review the config (bind address, data paths) before
LuraDB first runs; a notice at the end of the install says where the config
lives and how to start. The package ships its own `INSTALL.md`
(`/usr/share/doc/luradb/INSTALL.md`) with the full walkthrough: service
management, the admin key, HTTPS, the Unix-domain-socket path, updates and
removal.

## Try it with Docker

No Linux machine handy? Get a `.deb` — from the [Releases
page](https://github.com/hwein/luradb/releases) or built yourself — drop
it into `target/debian/` and run `docker compose up -d`; no Rust toolchain
or package install on the host. The container shares its host's kernel, so
the host (or the VM of Docker Desktop) needs Linux 6.1 or newer too. See
[packaging/docker/README.md](packaging/docker/README.md) for the
quickstart.

## Build from source

```sh
git clone https://github.com/hwein/luradb.git
cd luradb
git checkout main
cargo build --release
```

The toolchain is pinned in `rust-toolchain.toml`; `rustup` picks it up
automatically. To build the `.deb` package:

```sh
cargo install cargo-deb   # once
cargo deb
```

## Quick tour

Start the server (`cargo run` or the installed binary), then:

```sh
# Health check — no auth required
curl http://127.0.0.1:3000/health

# Admin API key — dev config ships a placeholder; the .deb package
# generates a real one into /etc/luradb/luradb.toml on install
grep api_key luradb.toml

# Key-value: write and read a key in the "default" domain
curl -X PUT http://127.0.0.1:3000/store-api/kv/default/keys/hello \
  -H "Authorization: Bearer lura_changeme_in_production" \
  -d 'world'
curl -i http://127.0.0.1:3000/store-api/kv/default/keys/hello \
  -H "Authorization: Bearer lura_changeme_in_production"

# Conditional write: replace the key only if it still has the ETag
# the read above returned (412 otherwise)
curl -X PUT http://127.0.0.1:3000/store-api/kv/default/keys/hello \
  -H "Authorization: Bearer lura_changeme_in_production" \
  -H 'If-Match: "<etag from the read>"' \
  -d 'world, again'

# JSON documents: create one in the "default" domain
curl -X POST http://127.0.0.1:3000/store-api/json/default/documents \
  -H "Authorization: Bearer lura_changeme_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "jane"}'
```

In development, a browsable Swagger UI is available at `/test-ui` (disabled
by default; the dev `luradb.toml` turns it on explicitly). With
`auth.enabled = true`, the UI and `/api-docs/openapi.json` need the same
valid API key as the rest of the API; use the UI's "Authorize" button to
set it.

Requests on one connection are processed in order (HTTP/1.1 pipelining and
HTTP/2 alike); open several connections for parallelism.

## MCP server

LuraDB ships an MCP server for AI assistants and agents (opt-in, `[mcp]` in
`luradb.toml`). It listens on its own port (3100 by default) on the
server's bind address and offers tools to list and describe domains, read
keys and documents, search, run SQL queries and read health and metrics.
Writing keys, documents and rows (`read_only = false`) and creating
domains, tables, views and indexes (`allow_ddl = true`) are separate
opt-ins; no tool deletes a domain, table, view or index. Clients
authenticate with an API key as Bearer token; clients that only speak OAuth
sign in once on a LuraDB page with their key when `oauth_enabled = true`
and `public_url` is set. Every tool runs with the permissions of that key.

## Multicore

LuraDB spreads its domains over several data shards by name; each shard is
one thread with its own storage engines. For one domain that means: reads
scale across cores — point reads run on the connection's thread, longer
reads on a pool of reader threads — while writes of one domain run on
exactly one core, the thread of its shard. Write parallelism is therefore
at most the number of domains being written at the same time; spread
independent write traffic over several domains.

The cores are split automatically between frontend workers (HTTP/TLS), data
shards and reader threads; `[multicore]` in `luradb.toml` overrides each
part. The shard count belongs to the data directory: the automatic setting
keeps the count an existing directory was written with, also after an
upgrade or a move to a host with another core count, and
`luradb --migrate-shards N` changes it while the server is stopped. Sizes,
memory per shard and the migration walkthrough:
[INSTALL.md "Multicore"](packaging/INSTALL.md#multicore) and
["Changing the shard count"](packaging/INSTALL.md#changing-the-shard-count).

## Disk and memory shortage

The server checks the free space of its data volumes and its own memory
use every second. Below the warn thresholds it logs a warning and
`GET /health` reports `degraded`; below the block thresholds it refuses
writes with `507 Insufficient Storage` and `Retry-After` while reads
continue, and resumes on its own once there is room again. While memory is
short it flushes its MemTables and returns heap to the kernel. Thresholds
are set in `[resources]` in `luradb.toml`; details in
[INSTALL.md "Disk and memory shortage"](packaging/INSTALL.md#disk-and-memory-shortage).

## Backups

A backup (`POST /store-api/backups`, or a schedule in `[backup]`) is a
logical NDJSON archive of key-value, JSON and relational domains: keys,
documents with their index definitions, and tables with their rows,
indexes, views and AUTOINCREMENT state. The scope picks what goes in: `all`,
one engine (`kv`, `json`, `rel`), one domain of one engine (`kv:<domain>`,
`json:<domain>`, `rel:<domain>`) or one domain name in every engine
(`domain:<name>`).

KVREF and JSONREF columns link to the KV and JSON domain of the same name.
They resolve after a restore when that domain is restored too or already
exists; otherwise they read as missing and are cleared, as after deleting
that domain. A restore under a new name (`into_domain`) links them to the
domains of the new name.

## License

LuraDB is Fair Source (FSL-1.1-ALv2): free to use, modify and redistribute
except to compete with LuraDB; each release converts to Apache 2.0 two
years after publication. See [LICENSE.md](LICENSE.md) for the full text.

## Security & Contributing

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please do not open
a public issue. For bug reports, feature proposals and code contributions,
see [CONTRIBUTING.md](CONTRIBUTING.md).
