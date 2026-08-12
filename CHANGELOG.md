# Changelog

All notable changes to LuraDB are documented in this file.

## [Unreleased]

### Added

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

[unreleased]: https://github.com/hwein/luradb/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/hwein/luradb/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/hwein/luradb/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hwein/luradb/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hwein/luradb/releases/tag/v0.1.0
