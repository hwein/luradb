# Changelog

All notable changes to LuraDB are documented in this file.

## [Unreleased]

### Added

- **BREAKING** API: `GET /store-api/auth/users` responses now include a `permissions` array per user (`{domain, store_type, access}`), mirroring the write-endpoint vocabulary.
- **BREAKING** API: added `GET /store-api/auth/whoami`, returning the caller's identity (`{name, role}`) for any authenticated caller — not admin-only. `role` is `"Admin"`, `"User"`, or a pseudo-role (`"TrustedPeer"`, `"Disabled"`).
- **BREAKING** API: added `GET /store-api/kv/{domain}/keys/{key}/meta`, returning a key's TTL expiry and last-modified time (`{expires_at, last_modified_at}`) without reading its value. `GET /store-api/kv/{domain}/keys/{key}` now also carries an `X-Expires-At` response header when the key has a TTL.
- **BREAKING** API: added `GET /store-api/kv/{domain}/count` (optional `?prefix=`) and `GET /store-api/rel/{domain}/tables/{table}/count`, each returning `{"count": N}` — a full key/row scan, same cost as listing.
- **BREAKING** API: `GET /store-api/kv/{domain}/watch` SSE events now carry an `id:` field, and the endpoint accepts `Last-Event-ID` (header, takes precedence) or `?last_event_id=` (query) to resume gaplessly from an in-memory replay ring; a new `reset` event type is emitted whenever gapless resume can't be guaranteed (window exceeded, server restart, or a lagged consumer). New `[lsm].watch_replay_buffer_size` config key controls the ring size (`0` disables resume).
- **BREAKING** API: added `GET /store-api/events`, an SSE stream of lifecycle/DDL events across the KV, JSON and relational engines (domain created/deleted/purged; rel table/view/index DDL; JSON index DDL) — admin-only, no per-key data events. Same `id:`/`Last-Event-ID`/`reset` resume mechanism as the KV watch, with its own tag and sequence. New `[events]` config section (`channel_capacity`, `replay_buffer_size`).
- **BREAKING** API: `PUT /store-api/json/{domain}/documents/{key}` now supports create-only writes via `If-None-Match: *`, answering `412 Precondition Failed` if the document already exists; only the literal `*` is supported, and combining it with `If-Match` answers `400`.
- **BREAKING** API: added `DELETE /store-api/kv/{domain}/keys?prefix={p}&contains={s}`, deleting every matching key in one atomic write batch and returning `{"deleted": N}`; `prefix` is required and non-empty (a domain-emptying request still needs the admin-only domain delete), and a selection over the new `[domains].max_bulk_delete_keys` limit (default 10,000) answers `413` with nothing deleted.
- **BREAKING** API: `POST /store-api/json/{domain}/documents`, `PUT /store-api/json/{domain}/documents/{key}`, and `GET /store-api/json/{domain}/documents/{key}` now document their response body as `DocumentResponse` (`_key`, `_version`, plus the document's own fields) in the OpenAPI contract — the JSON returned on the wire is unchanged.
- **BREAKING** API: `GET /store-api/metrics` now includes an `engines` block (`kv`/`json`/`rel`), each with `read_ops`, `write_ops`, `read_latency_us_p50/p95/p99`, `write_latency_us_p50/p95/p99`, and `window_secs` — per-engine op counts and latency percentiles over the rolling metrics window, alongside the existing KV-only `domains[]`.
- Optional CORS support via the new `[cors]` config section — an opt-in `CorsLayer` (exact origin allow-list, or `"*"`) lets browser clients call the API directly without a proxy in front; off by default.
- **BREAKING** API: added `GET /store-api/config`, returning the effective configuration of the running process (`config_path`, `config_file_loaded`, `config`) — admin-only; the admin API key is redacted from `config`, everything else is the same field names as the TOML file.
- Startup now fails fast when `max_value_size` or `max_key_length` of any engine's `[lsm]` block exceed the WAL recovery field cap — previously such a config wrote WAL records that only failed the *next* restart's recovery.
- **BREAKING** API: JSON document-store OpenAPI contract now documents `410 Gone` on all document/index/search/bulk/reindex routes, `If-Match` as a header parameter on `PUT`/`DELETE …/documents/{key}`, the `ETag` response header on `GET …/documents/{key}`, `DocumentListResponse`/`SearchResponse` document lists typed as `DocumentResponse[]`, and `text/plain` string bodies on every 4xx/5xx response in the JSON API.
- **BREAKING** API: every documented 4xx/5xx error response across the rest of the REST API (KV, domains, relational store/browse/rows, auth, backup/restore, logs, metrics, global events) now documents its body as a `text/plain` string in the OpenAPI contract, same as the JSON API above — wire format unchanged, previously undocumented; a new contract test enforces this on every current and future route.
- **BREAKING** API: `POST /store-api/json/{domain}/documents` and `PUT /store-api/json/{domain}/documents/{key}` now reject a top-level `_key`, `_version`, or `_content` field in the request body with `400` — these are reserved store-metadata names that a document could previously carry but never actually round-trip through: shadowed by the same-named metadata on every read, and unsafe across NDJSON export/re-import. `POST /store-api/json/{domain}/bulk` (and restore, which shares the same import path) now counts such a line as a per-document import error (`failed`/`errors`) instead of importing it; nested occurrences (e.g. `{"a": {"_key": 1}}`) are unaffected, and documents written before this change stay stored and readable as before.

### Security

- Rel: LIKE matching no longer allocates a table sized by pattern × text length.
- Rel: pathologically self-similar LIKE patterns now abort with an error instead of monopolizing a CPU core per row.
- Auth: rotating an API key now immediately invalidates the previous one — it used to stay valid in the cache until a second restart.
- **BREAKING** Rel: cross-engine KVREF/JSONREF links now require read access to the target KV/JSON domain. `/sql` expand of a column the caller can't read now returns `null` instead of the resolved value; INSERT/UPDATE (via `/sql` or row writes) with such a link now answers 403 instead of succeeding or 409.
- The server refuses to start with authentication disabled on a non-loopback bind — a config without `[auth]`, or a bind to `0.0.0.0`/`::` with `auth.enabled = false`, previously started silently with unauthenticated, network-wide access.
- **BREAKING** API: the Swagger UI and `/api-docs/openapi.json` now require a valid API key when `auth.enabled = true` (previously open regardless — the same server-version fingerprint that `GET /version` was hardened against was still readable from the OpenAPI contract). `server.swagger_enabled` now defaults to `false`.
- The Docker try image no longer embeds a generated admin key in an image layer — the key is now generated in the running container on first start instead.

### Changed

- **BREAKING** API: `POST /store-api/auth/users/{name}/permissions` now checks domain existence for `json`/`rel` store types when their engine is active — a missing domain now answers `404` (previously `200`), matching the existing `kv` behavior. New opt-in query parameter `?allow_missing=true` skips the existence check for all three store types (pre-provisioning), now including `kv` for the first time; domain name validation (`400`) applies to `json`/`rel` unconditionally and to `kv` only when `allow_missing=true`.
- **BREAKING** `server.bind_address` now defaults to `127.0.0.1` (previously `0.0.0.0`). Only affects a start without a config file, or one that omits `bind_address`; both shipped configs (`luradb.toml`, `packaging/luradb.toml`) already bind loopback explicitly.
- JSON document writes on different keys no longer serialize behind one engine-global lock.
- KV: expired keys are now removed proactively and emit a `delete` event — a background TTL sweeper tombstones them instead of leaving them to the next compaction, so watch subscribers see the expiry and the space comes back earlier. New `[ttl_sweeper]` config section (`enabled`, `interval_secs`, `batch_size`); `enabled = false` restores the previous purely lazy behavior.

### Fixed

- SSTable: a corrupted bloom filter block (empty bit array with a non-zero hash count) fails with an error instead of a panic.
- LSM: shutdown with a failed flush no longer truncates the WAL.
- LSM: startup fails loudly instead of silently skipping an unopenable SSTable.
- LSM: a restarted engine now seeds its clock from the recovered WAL and manifest — after a backwards system-clock step it no longer hides existing data or buries a rewritten key under its older version.
- LSM: a concurrent flush/compaction/GC save can no longer persist a stale manifest.
- LSM: a corrupt WAL length field fails recovery instead of allocating up to 4 GiB.
- Rel: a `SELECT … LIMIT` without ORDER BY no longer returns a short page when concurrent inserts land in the capped scan window.
- Rel: reads resolve their candidate rows against the statement snapshot on every access path, so concurrently deleted rows no longer vanish mid-query and the unindexed-join budget counts only visible rows.
- LSM: a MemTable rotation can no longer strand an in-flight write's older version above a newer one, which made reads return stale data.
- KV: watch events are now emitted after the write is applied, narrowing the window in which a delete racing a concurrent set broadcasts a state that never becomes visible.
- LSM: the `/metrics` fields `compaction_runs`, `janitor_runs` and `memtable_size_bytes` report real values instead of constant zero.

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
