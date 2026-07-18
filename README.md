<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/luradb-wordmark.svg">
  <img src=".github/luradb-wordmark-light.svg" alt="LuraDB" height="40">
</picture>

LuraDB is a Linux-first, REST-native multi-model database built on io_uring.
One small, fast process covers the three shapes of data a typical backend
needs: a key-value store (TTLs, watches), JSON documents (indexes, queries),
and slim relational tables (views, left joins). Its interface is a RESTful
API — no proprietary protocol, no driver stack to install: every language
and standard tool can talk to it out of the box, and the API is browsable
down to the individual record.

**Built for the small jobs, done well.** Typical homes for LuraDB:

- The state store behind an installer, provisioning routine or automation
  agent on a Linux machine — bare metal, WSL or a container.
- The backend of a website or small web app: sessions and tokens with TTL,
  a bunch of JSON documents, a few relational tables — without running
  Redis, MongoDB and PostgreSQL side by side.
- A local sidecar for services, scripts and cron jobs on the same host,
  reachable over a Unix domain socket instead of the TCP stack.
- Self-hosted services and home labs, where the database should install in
  one step, run under systemd, log to journald — and otherwise stay out of
  the way.
- Prototypes and internal tools that want a real, persistent store in
  minutes and can grow from keys to documents to tables without switching
  systems.

**What LuraDB is not.** LuraDB does not aim to be Oracle, PostgreSQL or
MySQL — nor MongoDB, Cassandra or Spark. There is no analytical engine, no
distributed cluster, no data-warehouse ambition: if your project needs a
Data Vault, you have outgrown LuraDB — and that is by design. Features earn
their place by making the small case better, not by making LuraDB bigger.

**Why "Lura"?** **L**inux + io_**ur**ing + **a**sync — the letters the
architecture is built on.

LuraDB is your friendly neighborhood database.

## Status

LuraDB is `0.x`, pre-1.0 software. On-disk formats and the REST API can
change between minor releases. See [CHANGELOG.md](CHANGELOG.md) for what
changed in each release — entries touching the REST API are marked `API:`,
breaking changes are marked **BREAKING**.

## Requirements

- Linux, amd64.
- A modern kernel with io_uring support — kernel ≥ 5.15 recommended.
- systemd, if you install the `.deb` package (LuraDB runs as a systemd
  service).

## Install

Download the latest `.deb` from the newest [GitHub
Release](https://github.com/hwein/luradb/releases) and install it:

```sh
sudo apt install ./luradb_*.deb
```

`apt` resolves the runtime dependencies, creates the `luradb` system user,
generates an admin API key and starts the systemd service. The package
ships its own `INSTALL.md` (`/usr/share/doc/luradb/INSTALL.md`) with the
full walkthrough: service management, the admin key, the Unix-domain-socket
path, updates and removal.

Releases publish prebuilt binaries starting with the first tagged version;
earlier, untagged history makes no binary guarantee.

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
curl http://127.0.0.1:3000/store-api/kv/default/keys/hello \
  -H "Authorization: Bearer lura_changeme_in_production"

# JSON documents: create one in the "default" domain
curl -X POST http://127.0.0.1:3000/store-api/json/default/documents \
  -H "Authorization: Bearer lura_changeme_in_production" \
  -H "Content-Type: application/json" \
  -d '{"name": "jane"}'
```

In development, a browsable Swagger UI is available at `/test-ui` (disabled
by default in the packaged/production config).

## License

LuraDB is Fair Source (FSL-1.1-ALv2): free to use, modify and redistribute
except to compete with LuraDB; each release converts to Apache 2.0 two
years after publication. See [LICENSE.md](LICENSE.md) for the full text.

## Security & Contributing

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please do not open
a public issue. For bug reports, feature proposals and code contributions,
see [CONTRIBUTING.md](CONTRIBUTING.md).
