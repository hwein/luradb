# Changelog

All notable changes to LuraDB are documented in this file.

## [Unreleased]

### Security

- Upgraded rkyv to 0.8.17+, resolving RUSTSEC-2026-0235 and removing the scan exception.

### Changed

- **BREAKING** on-disk format: stores written by v0.1.1 or earlier are incompatible and must be rebuilt.
- API: OpenAPI descriptions and CLI help text are now in English (previously partly German).

### Fixed

- API: `PATCH /store-api/kv/{domain}/keys/{key}/null` now sets a real null value state instead of deleting the key: the key stays registered and listed in scans, `GET` answers `204 No Content` (previously a wrong 404), and only `DELETE`/TTL expiry remove it. **Breaking** status-code Change.

## [0.1.1] - 2026-08-11

### Security

- Security scans: RUSTSEC-2026-0235 (rkyv 0.7) ignored as not exploitable in LuraDB.

## [0.1.0] - 2026-07-18

### Added

- Initial release of the LuraDB server: key-value, JSON document, and slim-relational engines behind a single REST API, with token-based authentication, TLS/reverse-proxy support, and a Debian package with systemd integration.

### Security

- Removed the unmaintained `bincode` 1.x dependency (declared but unused) and dropped `proc-macro-error` by upgrading utoipa to 5 — resolves the RUSTSEC-2025-0141 and RUSTSEC-2024-0370 scan exceptions.

[unreleased]: https://github.com/hwein/luradb/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/hwein/luradb/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hwein/luradb/releases/tag/v0.1.0
