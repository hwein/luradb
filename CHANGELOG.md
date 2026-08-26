# Changelog

All notable changes to LuraDB are documented in this file.

## [Unreleased]

### Security

- Rel: LIKE matching no longer allocates a table sized by pattern × text length.
- Auth: rotating an API key now immediately invalidates the previous one — it used to stay valid in the cache until a second restart.
- **BREAKING** Rel: cross-engine KVREF/JSONREF links now require read access to the target KV/JSON domain. `/sql` expand of a column the caller can't read now returns `null` instead of the resolved value; INSERT/UPDATE (via `/sql` or row writes) with such a link now answers 403 instead of succeeding or 409.
- The server refuses to start with authentication disabled on a non-loopback bind — a config without `[auth]`, or a bind to `0.0.0.0`/`::` with `auth.enabled = false`, previously started silently with unauthenticated, network-wide access.
- **BREAKING** API: the Swagger UI and `/api-docs/openapi.json` now require a valid API key when `auth.enabled = true` (previously open regardless — the same server-version fingerprint that `GET /version` was hardened against was still readable from the OpenAPI contract). `server.swagger_enabled` now defaults to `false`.
- The Docker try image no longer embeds a generated admin key in an image layer — the key is now generated in the running container on first start instead.

### Changed

- **BREAKING** `server.bind_address` now defaults to `127.0.0.1` (previously `0.0.0.0`). Only affects a start without a config file, or one that omits `bind_address`; both shipped configs (`luradb.toml`, `packaging/luradb.toml`) already bind loopback explicitly.

### Fixed

- SSTable: a corrupted bloom filter block (empty bit array with a non-zero hash count) fails with an error instead of a panic.

## [0.3.1] - 2026-08-13

### Fixed

- KV: a TTL of `n` seconds now holds for at least `n` seconds. Expiry stamps are whole seconds and the sub-second remainder was dropped, so entries expired up to a second early — a 1-second TTL could be gone within milliseconds.

## [0.3.0] - 2026-08-13

### Added

- API: logical backup & restore — consistent NDJSON export per scope (`all`, engine, single domain) with on-demand jobs, cron schedules with retention, download/upload, and restore with optional domain remapping (admin-only, opt-in via `backup.enabled`). Covers the KV and JSON engines only — relational data is not included yet.
- API: read-only log access — `GET /store-api/logs` (tail with `lines`/`q`/`file`) and `GET /store-api/logs/files` (file listing), admin-only, opt-in via `log.http_access`.
- `packaging/docker/`: Docker try-setup (Dockerfile, compose.yaml, entrypoint) that installs a user-provided `.deb` from `target/debian/` to run LuraDB via `docker compose up -d` without a Rust toolchain or Linux host.

### Fixed

- API: `/health` now reports the crate version (previously hardcoded `0.1.0`).

## [0.2.1] - 2026-08-12

### Security

- Replaced the retired `rustls-pemfile` dependency with `rustls-pki-types` PEM loading (RUSTSEC-2025-0134).

## [0.2.0] - 2026-08-12

### Added

- Native HTTPS listener: separate port, opt-in (`server.tls_enabled`).

### Security

- Upgraded rkyv to 0.8.17+, resolving RUSTSEC-2026-0235 and removing the scan exception.

### Changed

- **BREAKING** on-disk format: stores written by v0.1.1 or earlier are incompatible and must be rebuilt.
- API: OpenAPI descriptions and CLI help text are now in English (previously partly German).

### Fixed

- vLog GC no longer loses values that were only MemTable-resident or written concurrently.
- vLog GC now waits for in-flight writes before collecting, closing the last liveness window.
- SSTable: corrupted block handles fail with an error instead of a panic.
- API: `PATCH /store-api/kv/{domain}/keys/{key}/null` now sets a real null value state instead of deleting the key: the key stays registered and listed in scans, `GET` answers `204 No Content` (previously a wrong 404), and only `DELETE`/TTL expiry remove it. **Breaking** status-code Change.
- Storage-thread vLog I/O now validates the generation, and the active generation is routed through the thread after restart.

## [0.1.1] - 2026-08-11

### Security

- Security scans: RUSTSEC-2026-0235 (rkyv 0.7) ignored as not exploitable in LuraDB.

## [0.1.0] - 2026-07-18

### Added

- Initial release of the LuraDB server: key-value, JSON document, and slim-relational engines behind a single REST API, with token-based authentication, TLS/reverse-proxy support, and a Debian package with systemd integration.

### Security

- Removed the unmaintained `bincode` 1.x dependency (declared but unused) and dropped `proc-macro-error` by upgrading utoipa to 5 — resolves the RUSTSEC-2025-0141 and RUSTSEC-2024-0370 scan exceptions.

[unreleased]: https://github.com/hwein/luradb/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/hwein/luradb/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/hwein/luradb/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/hwein/luradb/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/hwein/luradb/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hwein/luradb/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hwein/luradb/releases/tag/v0.1.0
