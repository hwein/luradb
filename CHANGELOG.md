# Changelog

All notable changes to LuraDB are documented in this file.

## [Unreleased]

### Fixed

- API: `PATCH /store-api/kv/{domain}/keys/{key}/null` now sets a real null value state instead of deleting the key (concept 001 §2b): the key stays registered and listed in scans, `GET` answers `204 No Content` (previously a wrong 404), and only `DELETE`/TTL expiry remove it. Breaking status-code change — API contract version bumped to 1.0.0.

## [0.1.0] - 2026-07-18

### Added

- Initial release of the LuraDB server: key-value, JSON document, and slim-relational engines behind a single REST API, with token-based authentication, TLS/reverse-proxy support, and a Debian package with systemd integration.

### Security

- Removed the unmaintained `bincode` 1.x dependency (declared but unused) and dropped `proc-macro-error` by upgrading utoipa to 5 — resolves the RUSTSEC-2025-0141 and RUSTSEC-2024-0370 scan exceptions.


[unreleased]: https://github.com/hwein/luradb/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hwein/luradb/releases/tag/v0.1.0
