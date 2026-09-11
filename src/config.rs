use crate::core::wal::WAL_MAX_FIELD_LEN;
use crate::engines::json::domain as json_domain;
use crate::engines::rel::{catalog as rel_catalog, row::ROW_HEADER_LEN};
use serde::de::{self, value::StrDeserializer, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LuraConfig {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub io_engine: IoEngineConfig,
    pub buffer_pool: BufferPoolConfig,
    pub lsm: LsmConfig,
    pub compaction: CompactionCfg,
    pub janitor: JanitorCfg,
    pub ttl_sweeper: TtlSweeperCfg,
    pub domains: DomainsConfig,
    pub rate_limit: RateLimitConfig,
    pub log: LogConfig,
    pub auth: AuthConfig,
    pub proxy: ProxyConfig,
    pub json: JsonStoreConfig,
    pub rel: RelStoreConfig,
    pub shm: ShmConfig,
    pub backup: BackupConfig,
    pub events: EventsConfig,
    pub cors: CorsConfig,
    pub multicore: MulticoreConfig,
}

impl Default for LuraConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            io_engine: IoEngineConfig::default(),
            buffer_pool: BufferPoolConfig::default(),
            lsm: LsmConfig::default(),
            compaction: CompactionCfg::default(),
            janitor: JanitorCfg::default(),
            ttl_sweeper: TtlSweeperCfg::default(),
            domains: DomainsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            log: LogConfig::default(),
            auth: AuthConfig::default(),
            proxy: ProxyConfig::default(),
            json: JsonStoreConfig::default(),
            rel: RelStoreConfig::default(),
            shm: ShmConfig::default(),
            backup: BackupConfig::default(),
            events: EventsConfig::default(),
            cors: CorsConfig::default(),
            multicore: MulticoreConfig::default(),
        }
    }
}

impl LuraConfig {
    /// Loads config from `path` plus its unknown keys (see [`Self::parse`]).
    /// Returns `Default` if the file does not exist.
    pub fn load(path: &Path) -> anyhow::Result<(Self, Vec<String>)> {
        if !path.exists() {
            return Ok((Self::default(), Vec::new()));
        }
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content).map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))
    }

    /// Parses config text. Also returns the keys it sets that the server does
    /// not read, sorted and deduplicated; they are ignored (spec general/030).
    pub fn parse(content: &str) -> Result<(Self, Vec<String>), toml::de::Error> {
        let config = toml::from_str(content)?;
        let mut keys = Vec::new();
        toml_keys(&content.parse()?, "", &mut keys);
        Ok((config, unknown_keys(keys, &known_keys())))
    }

    /// Rejects data paths that share a real location or land on a vLog
    /// generation file `<vlog_path>.<n>`; relative paths resolve against `base`.
    pub fn validate_data_paths(&self, base: &Path) -> anyhow::Result<()> {
        let mut entries: Vec<(&str, &str, bool)> = vec![
            ("storage.db_path", self.storage.db_path.as_str(), false),
            ("storage.wal_path", self.storage.wal_path.as_str(), false),
            ("storage.vlog_path", self.storage.vlog_path.as_str(), true),
            ("storage.sstable_dir", self.storage.sstable_dir.as_str(), false),
        ];
        if self.json.enabled {
            entries.push(("json.wal_path", self.json.wal_path.as_str(), false));
            entries.push(("json.vlog_path", self.json.vlog_path.as_str(), true));
            entries.push(("json.sstable_dir", self.json.sstable_dir.as_str(), false));
        }
        if self.rel.enabled {
            entries.push(("rel.wal_path", self.rel.wal_path.as_str(), false));
            entries.push(("rel.vlog_path", self.rel.vlog_path.as_str(), true));
            entries.push(("rel.sstable_dir", self.rel.sstable_dir.as_str(), false));
        }
        if self.backup.enabled {
            entries.push(("backup.dir", self.backup.dir.as_str(), false));
        }
        let paths = entries
            .into_iter()
            .map(|(key, raw, is_vlog)| DataPath::new(base, key, raw, is_vlog))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Rule 1: no two resolved locations coincide.
        for (i, a) in paths.iter().enumerate() {
            if let Some(b) = paths[i + 1..].iter().find(|b| b.resolved == a.resolved) {
                return Err(same_location(a.key, b.key, &a.resolved));
            }
        }

        // Rule 2: no location is a vLog generation file. The entry's slot counts
        // too: the vLog would write that file through a symlink placed there.
        for vlog in paths.iter().filter(|p| p.is_vlog) {
            let vlog_name = vlog.slot.file_name().unwrap_or_default();
            for entry in paths.iter().filter(|p| p.key != vlog.key) {
                for location in [&entry.resolved, &entry.slot] {
                    if location.parent() == vlog.slot.parent()
                        && matches_generation_name(location.file_name(), vlog_name)
                    {
                        return Err(same_location(vlog.key, entry.key, location));
                    }
                }
            }
        }
        Ok(())
    }
}

/// A data path resolved once. `slot` is its resolved parent plus its own file
/// name, where vLog generation files go; it differs from `resolved` when the
/// last segment is a symlink.
struct DataPath<'a> {
    key: &'a str,
    resolved: PathBuf,
    slot: PathBuf,
    is_vlog: bool,
}

impl<'a> DataPath<'a> {
    fn new(base: &Path, key: &'a str, raw: &str, is_vlog: bool) -> anyhow::Result<Self> {
        let path = base.join(raw);
        let resolve = |p: &Path| resolve_real_path(p).map_err(|e| anyhow::anyhow!("invalid config: {key} {e}"));
        let resolved = resolve(&path)?;
        let slot = resolve(path.parent().unwrap_or(Path::new("/")))?.join(path.file_name().unwrap_or_default());
        Ok(Self { key, resolved, slot, is_vlog })
    }
}

fn same_location(a: &str, b: &str, location: &Path) -> anyhow::Error {
    anyhow::anyhow!("invalid config: {a} and {b} resolve to the same location '{}'", location.display())
}

/// Linux's MAXSYMLINKS; ends symlink loops.
const MAX_SYMLINK_HOPS: u32 = 40;

/// Owned `Component`, so symlink targets can be spliced into the queue.
enum PathPart {
    Root,
    CurDir,
    ParentDir,
    Normal(OsString),
}

fn path_parts(p: &Path) -> VecDeque<PathPart> {
    p.components()
        .map(|c| match c {
            Component::RootDir => PathPart::Root,
            Component::CurDir => PathPart::CurDir,
            Component::ParentDir => PathPart::ParentDir,
            Component::Normal(name) => PathPart::Normal(name.to_os_string()),
            Component::Prefix(_) => unreachable!(),
        })
        .collect()
}

/// Resolves `path` component by component, following symlinks like the
/// kernel; components that do not exist stay lexical.
fn resolve_real_path(path: &Path) -> anyhow::Result<PathBuf> {
    let mut pending = path_parts(path);
    let mut resolved = PathBuf::new();
    let mut hops = 0u32;

    while let Some(part) = pending.pop_front() {
        match part {
            PathPart::Root => resolved = PathBuf::from("/"),
            PathPart::CurDir => {}
            PathPart::ParentDir => {
                resolved.pop();
            }
            PathPart::Normal(name) => {
                resolved.push(&name);
                // Dangling symlinks are followed too: the engines open with
                // O_CREAT and would create the target.
                let is_symlink = std::fs::symlink_metadata(&resolved)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false);
                if is_symlink {
                    hops += 1;
                    anyhow::ensure!(hops <= MAX_SYMLINK_HOPS, "has more than {MAX_SYMLINK_HOPS} symlink hops");
                    let target = std::fs::read_link(&resolved)
                        .map_err(|e| anyhow::anyhow!("has an unreadable symlink '{}': {e}", resolved.display()))?;
                    // A relative target continues from the symlink's directory;
                    // a later `..` then acts on the target, not on the link.
                    resolved.pop();
                    let mut next = path_parts(&target);
                    next.extend(pending);
                    pending = next;
                }
            }
        }
    }
    Ok(resolved)
}

/// True if `candidate` is `<vlog_filename>.<digits>`. Any digits count, even
/// `.0`/`.1`, which the vLog never writes (spec rule 2).
fn matches_generation_name(candidate: Option<&OsStr>, vlog_filename: &OsStr) -> bool {
    let Some(candidate) = candidate else { return false };
    let candidate = candidate.as_bytes();
    let prefix = vlog_filename.as_bytes();
    if candidate.len() <= prefix.len() + 1 || candidate[..prefix.len()] != *prefix || candidate[prefix.len()] != b'.' {
        return false;
    }
    candidate[prefix.len() + 1..].iter().all(u8::is_ascii_digit)
}

/// Resolves the effective config path when `--config` was not given:
/// `./luradb.toml` (dev workflow) takes priority over `/etc/luradb/luradb.toml`
/// (installed deb); if neither exists, falls back to the dev default path
/// unchanged (caller logs "using defaults", `LuraConfig::load` returns
/// `Default`). `exists` is injected so this stays pure/testable.
pub fn resolve_config_path(cli_arg: Option<PathBuf>, exists: impl Fn(&Path) -> bool) -> PathBuf {
    if let Some(path) = cli_arg {
        return path;
    }
    let dev_default = PathBuf::from("luradb.toml");
    if exists(&dev_default) {
        return dev_default;
    }
    let installed = PathBuf::from("/etc/luradb/luradb.toml");
    if exists(&installed) {
        return installed;
    }
    dev_default
}

// ── Server ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    /// TCP bind address for the HTTP/HTTPS listeners. Defaults to loopback,
    /// not `0.0.0.0` (spec general/013: fail-closed with auth disabled).
    pub bind_address: String,
    pub port: u16,
    /// Set to `true` to enable the Swagger UI + `/api-docs/openapi.json`
    /// (default: `false`, safe for production). When `auth.enabled = true`,
    /// these docs routes require the same "any valid key, no domain
    /// permission" check as `GET /version` (spec 004 §7; enforced by
    /// `auth::middleware::docs_auth_layer`, spec general/014) — when auth is
    /// disabled, they're served openly like everything else.
    pub swagger_enabled: bool,
    /// URL path at which Swagger UI is served (default: `/test-ui`).
    pub swagger_url: String,
    /// Whether to register the root `/` hello-handler route.
    pub hello_enabled: bool,
    /// Response message returned by the hello-handler.
    pub hello_message: String,
    /// Absolute path for the Unix Domain Socket. `None` = UDS disabled.
    pub unix_socket_path: Option<String>,
    /// Set to `false` to disable the plain HTTP listener (spec general/011).
    pub http_enabled: bool,
    /// Enables the native HTTPS listener on `tls_port` (spec general/011).
    pub tls_enabled: bool,
    /// Port for the native HTTPS listener. Must differ from `port`.
    pub tls_port: u16,
    /// PEM certificate (optionally with chain) for the native HTTPS listener.
    pub tls_cert_path: String,
    /// PEM private key (PKCS#8, RSA, or EC) for the native HTTPS listener.
    pub tls_key_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 3000,
            swagger_enabled: false,
            swagger_url: "/test-ui".to_string(),
            hello_enabled: true,
            hello_message: "Hello from LuraDB".to_string(),
            unix_socket_path: None,
            http_enabled: true,
            tls_enabled: false,
            tls_port: 3443,
            tls_cert_path: "/etc/luradb/tls/server.crt".to_string(),
            tls_key_path: "/etc/luradb/tls/server.key".to_string(),
        }
    }
}

impl ServerConfig {
    /// Startup validation (spec general/011): at least one TCP listener must
    /// be enabled, and HTTP/HTTPS cannot share the same port. Cert/key
    /// readability and parsability are checked when the TLS listener is
    /// actually built (`tls::load_tls_acceptor`), not here.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.http_enabled || self.tls_enabled,
            "invalid config: server.http_enabled and server.tls_enabled are both false — no listener would start"
        );
        anyhow::ensure!(
            self.tls_port != self.port,
            "invalid config: server.tls_port ({}) must differ from server.port ({})",
            self.tls_port,
            self.port
        );
        Ok(())
    }
}

// ── Storage ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    pub db_path: String,
    pub wal_path: String,
    pub vlog_path: String,
    pub sstable_dir: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: "luradb.db".to_string(),
            wal_path: "luradb.wal".to_string(),
            vlog_path: "luradb.vlog".to_string(),
            sstable_dir: "luradb_sstables".to_string(),
        }
    }
}

// ── IO Engine (spec perf/004) ──────────────────────────────────────────────────

/// Registered-buffer I/O via tokio-uring 0.5's `FixedBufPool`.
///
/// Scaffolding only — not yet wired into the WAL/VLog/SSTable hot paths
/// (see spec perf/004). Disabled by default.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct IoEngineConfig {
    /// Enables the IoEngine (Default: false). Also gates the perf/005 storage thread.
    pub enabled: bool,
}

impl Default for IoEngineConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

// ── Buffer Pool ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct BufferPoolConfig {
    pub pool_size: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self { pool_size: 1024 }
    }
}

// ── Block Cache (Spec 015) ─────────────────────────────────────────────────────

/// Block-cache sizing of one LSM instance. A parameter type, not a config
/// section: the engines pass fixed values (spec general/030).
#[derive(Debug)]
pub struct BlockCacheConfig {
    /// Maximum total size of the block cache in bytes (default: 64 MB).
    pub capacity_bytes: usize,
    /// Fraction of capacity reserved for the Small Queue (0.0–1.0, default: 0.10).
    pub small_ratio: f32,
    /// Maximum number of entries in the Ghost Buffer (metadata only).
    pub ghost_capacity: usize,
}

impl Default for BlockCacheConfig {
    fn default() -> Self {
        Self {
            capacity_bytes: 64 * 1024 * 1024, // 64 MB
            small_ratio: 0.10,
            ghost_capacity: 10_000,
        }
    }
}

// ── LSM Engine ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LsmConfig {
    pub vlog_inline_threshold: usize,
    pub memtable_size_threshold: usize,
    pub max_key_length: usize,
    pub max_value_size: usize,
    pub flush_check_interval_ms: u64,
    pub compaction_check_interval_ms: u64,
    pub wal_event_channel_capacity: usize,
    /// KV watch replay-ring capacity (spec kv/024). `0` disables resume —
    /// every reconnect with a `Last-Event-ID` gets `reset`, but `id:` fields
    /// are still assigned.
    pub watch_replay_buffer_size: usize,
}

impl Default for LsmConfig {
    fn default() -> Self {
        Self {
            vlog_inline_threshold: 1024,
            memtable_size_threshold: 4 * 1024 * 1024,
            max_key_length: 256,
            max_value_size: 512 * 1024,
            flush_check_interval_ms: 100,
            compaction_check_interval_ms: 1000,
            wal_event_channel_capacity: 256,
            watch_replay_buffer_size: 1024,
        }
    }
}

impl LsmConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        check_wal_field("lsm.max_value_size", self.max_value_size)?;
        check_wal_field("lsm.max_key_length", self.max_key_length)
    }
}

/// Startup validation (spec general/025): a key or value limit above
/// `WAL_MAX_FIELD_LEN` would still write today and only fail recovery on the
/// *next* restart -- reject it at startup instead.
fn check_wal_field(key: &str, value: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        value <= WAL_MAX_FIELD_LEN,
        "invalid config: {key} ({value}) exceeds the WAL recovery field cap ({WAL_MAX_FIELD_LEN} bytes) — writes this large could never be recovered"
    );
    Ok(())
}

/// Startup validation (spec general/030): rejects `value` below `min`.
fn check_min(key: &str, value: usize, min: usize) -> anyhow::Result<()> {
    anyhow::ensure!(value >= min, "invalid config: {key} ({value}) must be at least {min}");
    Ok(())
}

/// `[json.lsm]`: the JSON instance's key and value limits; its other LSM
/// settings are the engine defaults.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct JsonLsmConfig {
    pub max_key_length: usize,
    pub max_value_size: usize,
}

impl Default for JsonLsmConfig {
    fn default() -> Self {
        Self {
            max_key_length: 256,
            max_value_size: 512 * 1024,
        }
    }
}

/// Lower bound of `json.lsm.max_value_size` (spec general/030).
pub(crate) const JSON_LSM_MIN_VALUE_SIZE: usize = 4096;

impl JsonLsmConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        check_min("json.lsm.max_value_size", self.max_value_size, JSON_LSM_MIN_VALUE_SIZE)?;
        check_wal_field("json.lsm.max_value_size", self.max_value_size)?;
        check_min("json.lsm.max_key_length", self.max_key_length, json_domain::MIN_LSM_KEY_LENGTH)?;
        check_wal_field("json.lsm.max_key_length", self.max_key_length)
    }
}

/// `[rel.lsm]`: the relational instance's key limit. Its value limit derives
/// from `rel.max_row_size`; its other LSM settings are the engine defaults.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RelLsmConfig {
    pub max_key_length: usize,
}

impl Default for RelLsmConfig {
    fn default() -> Self {
        Self { max_key_length: 256 }
    }
}

impl RelLsmConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        check_min("rel.lsm.max_key_length", self.max_key_length, rel_catalog::MIN_LSM_KEY_LENGTH)?;
        check_wal_field("rel.lsm.max_key_length", self.max_key_length)
    }
}

// ── Compaction ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CompactionCfg {
    pub l0_threshold: usize,
    pub l1_max_size: u64,
    pub level_size_ratio: u64,
    pub max_sstable_size: usize,
}

impl Default for CompactionCfg {
    fn default() -> Self {
        Self {
            l0_threshold: 4,
            l1_max_size: 100 * 1024 * 1024,
            level_size_ratio: 10,
            max_sstable_size: 64 * 1024 * 1024,
        }
    }
}

// ── Janitor ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct JanitorCfg {
    pub check_interval_secs: u64,
    pub dead_bytes_threshold: f64,
    pub min_vlog_size_bytes: u64,
}

impl Default for JanitorCfg {
    fn default() -> Self {
        Self {
            check_interval_secs: 60,
            dead_bytes_threshold: 0.30,
            min_vlog_size_bytes: 64 * 1024 * 1024,
        }
    }
}

// ── TTL sweeper ───────────────────────────────────────────────────────────────

/// Background task that tombstones TTL-expired keys and emits their delete
/// events (spec kv/025). Only the KV instance runs one.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct TtlSweeperCfg {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Candidates *checked* per tick — discarded ones count too, so a tick may
    /// write fewer tombstones than this.
    pub batch_size: usize,
}

impl Default for TtlSweeperCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            batch_size: 500,
        }
    }
}

// ── Domains ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DomainsConfig {
    pub max_name_length: usize,
    pub max_user_key_length: usize,
    pub default_domain: String,
    pub purger_batch_size: usize,
    pub purger_interval_secs: u64,
    /// Cap on the number of keys a single `DELETE …/keys?prefix=` bulk
    /// delete (spec kv/023) may remove; a larger selection is rejected with
    /// 413 and nothing is deleted. `0` rejects every non-empty selection —
    /// not treated as "unlimited".
    pub max_bulk_delete_keys: usize,
}

impl Default for DomainsConfig {
    fn default() -> Self {
        Self {
            max_name_length: 50,
            max_user_key_length: 256,
            default_domain: "default".to_string(),
            purger_batch_size: 100,
            purger_interval_secs: 5,
            max_bulk_delete_keys: 10_000,
        }
    }
}

// ── Rate Limiting ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub default_read_iops: u32,
    pub default_write_iops: u32,
    /// `0` means no limit.
    pub default_max_storage_bytes: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_read_iops: 1000,
            default_write_iops: 500,
            default_max_storage_bytes: 0,
        }
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Set to `false` to disable auth enforcement (dev/local mode).
    pub enabled: bool,
    pub admins: Vec<AdminEntry>,
    /// UIDs authenticated via UDS peer credentials without an API key
    /// (admin access). Empty = UCred bypass disabled (perf/001).
    pub trusted_uids: Vec<u32>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            admins: Vec::new(),
            trusted_uids: Vec::new(),
        }
    }
}

impl AuthConfig {
    /// Fail-closed startup check (spec general/013): with auth disabled, the
    /// server may only serve loopback — otherwise anyone who reaches the
    /// listener gets unauthenticated full access. `#[serde(default)]` means
    /// a config without an `[auth]` section still reaches this check.
    pub fn validate(&self, server: &ServerConfig) -> anyhow::Result<()> {
        let bind: IpAddr = server.bind_address.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid config: server.bind_address '{}' is not a valid IP address: {e}",
                server.bind_address
            )
        })?;
        anyhow::ensure!(
            self.enabled || bind.is_loopback(),
            "invalid config: auth.enabled = false and server.bind_address = '{}' is not loopback — enable auth (auth.enabled = true) or bind to loopback (127.0.0.1 / ::1)",
            server.bind_address
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdminEntry {
    pub name: String,
    /// Secret, read on deserialize but never written back out. Convention:
    /// any new secret field in this file gets `#[serde(skip_serializing)]`
    /// the moment it's introduced — that's the only thing keeping it out of
    /// `GET /store-api/config` (spec general/022).
    #[serde(skip_serializing)]
    pub api_key: String,
}

// ── Logging ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Verbose,
    #[default]
    Info,
    Prod,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    /// Empty = stdout only; the directory is created if missing.
    pub path: String,
    /// "none" | "daily" | "hourly" — ignored when path is empty.
    pub rotation: String,
    /// 0 = never delete.
    pub retention_days: u64,
    pub modules: LogModulesConfig,
    /// Enables `GET /store-api/logs` + `/logs/files` (spec general/005).
    /// Requires `path` to be non-empty (stdout is not scrapeable).
    pub http_access: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            path: String::new(),
            rotation: "daily".to_string(),
            retention_days: 30,
            modules: LogModulesConfig::default(),
            http_access: false,
        }
    }
}

impl LogConfig {
    /// Startup validation (spec general/005, fail fast): HTTP log access
    /// needs file logging as its source, since stdout isn't scrapeable.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.http_access || !self.path.is_empty(),
            "invalid config: log.http_access requires log.path"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct LogModulesConfig {
    pub auth: Option<LogLevel>,
    pub api: Option<LogLevel>,
    pub engine: Option<LogLevel>,
    pub storage: Option<LogLevel>,
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// CIDR strings of trusted reverse-proxy IPs/ranges.
    /// Empty = no trusted-header evaluation (direct mode).
    pub trusted_proxies: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
        }
    }
}

// ── JSON Store (spec json/001) ────────────────────────────────────────────────

/// Config for the JSON engine's dedicated LSM instance (own paths & limits).
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct JsonStoreConfig {
    /// Set to `false` to skip starting the JSON engine entirely.
    pub enabled: bool,
    pub wal_path: String,
    pub vlog_path: String,
    pub sstable_dir: String,
    /// Max HTTP request-body size for `/json/{domain}/bulk` in bytes
    /// (default 64 MB). Raises axum's 2 MB default so NDJSON exports can be
    /// re-imported in one request.
    pub bulk_body_limit_bytes: usize,
    pub lsm: JsonLsmConfig,
}

impl Default for JsonStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            wal_path: "luradb_json.wal".to_string(),
            vlog_path: "luradb_json.vlog".to_string(),
            sstable_dir: "luradb_json_sstables".to_string(),
            bulk_body_limit_bytes: 64 * 1024 * 1024,
            lsm: JsonLsmConfig::default(),
        }
    }
}

impl JsonStoreConfig {
    /// Startup validation of the limits; runs even while the engine is
    /// disabled, since it can be switched on later (spec general/030).
    pub fn validate(&self) -> anyhow::Result<()> {
        check_min("json.bulk_body_limit_bytes", self.bulk_body_limit_bytes, 1)?;
        self.lsm.validate()
    }
}

// ── Relational Store (spec rel/001) ───────────────────────────────────────────

/// Config for the relational engine's dedicated LSM instance (own paths &
/// limits). No `db_path` — like the JSON engine, this LSM instance has no
/// buffer-pool/DiskManager stack, so there is no database file to point at.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RelStoreConfig {
    /// Set to `false` to skip starting the relational engine entirely.
    pub enabled: bool,
    pub wal_path: String,
    pub vlog_path: String,
    pub sstable_dir: String,
    /// Catalog limit (spec rel/003, concept 8).
    pub max_tables_per_domain: usize,
    /// DML write-path guard (spec rel/005, concept 8): max encoded LuraRow
    /// size. The engine's storage value limit is the larger of this and
    /// 512 KiB (spec general/030).
    pub max_row_size: usize,
    /// SELECT executor limits (spec rel/006, concept 8): the hard cap on any
    /// explicit LIMIT, and the hard cap on the in-memory ORDER BY sort buffer.
    pub max_limit: usize,
    pub max_sort_rows: usize,
    /// JOIN governance (spec rel/007, concept 8): whether an unindexed join
    /// column may fall back to a per-row full scan (dev/tiny-table escape
    /// hatch) instead of a 400.
    pub allow_unindexed_joins: bool,
    /// Body-size cap for `POST .../tables/from-file` (spec rel/019), analogous
    /// to `json.bulk_body_limit_bytes`.
    pub import_body_limit_bytes: usize,
    pub lsm: RelLsmConfig,
}

impl Default for RelStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            wal_path: "luradb_rel.wal".to_string(),
            vlog_path: "luradb_rel.vlog".to_string(),
            sstable_dir: "luradb_rel_sstables".to_string(),
            max_tables_per_domain: 256,
            max_row_size: 512 * 1024,
            max_limit: 10_000,
            max_sort_rows: 100_000,
            allow_unindexed_joins: false,
            import_body_limit_bytes: 64 * 1024 * 1024,
            lsm: RelLsmConfig::default(),
        }
    }
}

impl RelStoreConfig {
    /// Startup validation of the limits; runs even while the engine is
    /// disabled, since it can be switched on later (spec general/030).
    pub fn validate(&self) -> anyhow::Result<()> {
        // Table and index ids are u32.
        let max_tables = u32::MAX as usize;
        anyhow::ensure!(
            (1..=max_tables).contains(&self.max_tables_per_domain),
            "invalid config: rel.max_tables_per_domain ({}) must be between 1 and {max_tables}",
            self.max_tables_per_domain
        );
        check_min("rel.max_row_size", self.max_row_size, ROW_HEADER_LEN + 1)?;
        // The storage value limit is at least max_row_size.
        check_wal_field("rel.max_row_size", self.max_row_size)?;
        check_min("rel.max_limit", self.max_limit, 1)?;
        check_min("rel.max_sort_rows", self.max_sort_rows, 1)?;
        self.lsm.validate()
    }
}

// ── Shared Memory IPC (spec perf/006) ─────────────────────────────────────────

/// POSIX shared-memory segments for the local IPC bypass. Wire protocols on
/// top of these segments (state header, ringbuffer, RCU) follow in specs
/// 007-009.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct ShmConfig {
    /// Enables SHM segment setup at startup (Default: false).
    pub enabled: bool,
    /// Namespace suffix for segment/lock names — allows multiple instances
    /// on one host (Default: "0").
    pub instance_id: String,
    /// Size of each double-buffer data segment in bytes (Default: 256 MB).
    pub data_buffer_size: usize,
    /// UDS path for the multi-client registration listener; `{instance_id}`
    /// is substituted at runtime (Default: "/run/luradb/{instance_id}.sock").
    pub registration_socket_path: String,
    /// Interval in milliseconds at which the RCU snapshot publisher checks for
    /// changes (spec perf/009 §4, perf/028; Default: 100). A MemTable flush
    /// also triggers a check; the snapshot is rebuilt only after a change.
    pub snapshot_interval_ms: u64,
}

impl Default for ShmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            instance_id: "0".to_string(),
            data_buffer_size: 268_435_456,
            registration_socket_path: "/run/luradb/{instance_id}.sock".to_string(),
            snapshot_interval_ms: 100,
        }
    }
}

impl ShmConfig {
    /// Registration socket path with `{instance_id}` substituted.
    pub fn resolved_registration_socket_path(&self) -> String {
        self.registration_socket_path.replace("{instance_id}", &self.instance_id)
    }

    /// Validates the data buffer size, the instance id and the snapshot interval.
    pub fn validate(&self) -> anyhow::Result<()> {
        check_min("shm.data_buffer_size", self.data_buffer_size, 4096)?;
        // '_' would make the stale-scan prefix `luradb_{id}_` ambiguous across
        // instances (id "0" would match and unlink live segments of "0_backup").
        anyhow::ensure!(
            !self.instance_id.is_empty()
                && self.instance_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "invalid config: shm.instance_id ('{}') must be non-empty and contain only [A-Za-z0-9-]",
            self.instance_id
        );
        // 0 would turn the snapshot publisher into a busy loop of full scans.
        anyhow::ensure!(
            self.snapshot_interval_ms >= 1,
            "invalid config: shm.snapshot_interval_ms ({}) must be at least 1",
            self.snapshot_interval_ms
        );
        Ok(())
    }

    /// Startup validation (spec general/030), a no-op while SHM is off: the
    /// REST listener binds after the registration socket and would replace it.
    pub fn validate_registration_socket(&self, server: &ServerConfig) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let registration = self.resolved_registration_socket_path();
        anyhow::ensure!(
            server.unix_socket_path.as_deref().map(Path::new) != Some(Path::new(&registration)),
            "invalid config: shm.registration_socket_path ('{registration}') equals server.unix_socket_path — SHM clients could not register; use a different path"
        );
        Ok(())
    }
}

// ── Backup & Restore (spec general/006) ───────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct BackupConfig {
    /// Master switch. `false` = no scheduler task, backup endpoints answer 503.
    pub enabled: bool,
    /// Target directory for backup artifacts. Collisions with storage.*/
    /// json.*/rel.* paths are rejected by `LuraConfig::validate_data_paths`.
    pub dir: String,
    /// Zero to many schedules; without one there are only on-demand backups.
    /// `[[backup.schedule]]` in TOML (singular) maps to this plural Vec field.
    pub schedule: Vec<BackupScheduleConfig>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: "luradb_backups".to_string(),
            schedule: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackupScheduleConfig {
    /// Unique across all schedules; `[a-zA-Z0-9_-]{1,50}`.
    pub name: String,
    /// 5-field cron subset, evaluated in UTC (see `crate::backup::cron`).
    pub cron: String,
    /// See `crate::backup::BackupScope` for the grammar.
    pub scope: String,
    #[serde(default)]
    pub include_auth: bool,
    /// Retention: how many of this schedule's most recent backups to keep (>= 1).
    pub keep_last: usize,
}

/// A schedule must fire within 4 years including a leap day (spec general/030).
const CRON_HORIZON_DAYS: u64 = 4 * 365 + 1;

impl BackupConfig {
    /// Startup validation (spec general/006, fail fast). A no-op when
    /// `enabled = false` — a disabled backup config runs no scheduler and
    /// serves no endpoints, so its contents are never acted on.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_at(crate::engines::lsm::domain::now_secs())
    }

    /// [`Self::validate`] for the start time `now` (Unix seconds, UTC).
    fn validate_at(&self, now: u64) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(!self.dir.is_empty(), "invalid config: backup.dir must not be empty");

        let mut seen_names = std::collections::HashSet::new();
        for sched in &self.schedule {
            anyhow::ensure!(
                crate::auth::handlers::valid_name(&sched.name),
                "invalid config: backup.schedule.name ('{}') must be 1-50 characters of [a-zA-Z0-9_-]",
                sched.name
            );
            anyhow::ensure!(
                seen_names.insert(sched.name.clone()),
                "invalid config: backup.schedule.name ('{}') must be unique across schedules",
                sched.name
            );
            let cron = crate::backup::cron::CronSchedule::parse(&sched.cron).map_err(|e| {
                anyhow::anyhow!(
                    "invalid config: backup.schedule.cron ('{}') is not a valid cron expression: {e} (schedule '{}')",
                    sched.cron,
                    sched.name
                )
            })?;
            anyhow::ensure!(
                cron.fires_within_days(now, CRON_HORIZON_DAYS),
                "invalid config: backup.schedule.cron ('{}') has no date within 4 years — the schedule would never run (schedule '{}')",
                sched.cron,
                sched.name
            );
            crate::backup::BackupScope::parse(&sched.scope).map_err(|e| {
                anyhow::anyhow!(
                    "invalid config: backup.schedule.scope ('{}') is not a valid scope: {e} (schedule '{}')",
                    sched.scope,
                    sched.name
                )
            })?;
            anyhow::ensure!(
                sched.keep_last >= 1,
                "invalid config: backup.schedule.keep_last ({}) must be at least 1 (schedule '{}')",
                sched.keep_last,
                sched.name
            );
        }
        Ok(())
    }
}

// ── Global event stream (spec general/018) ────────────────────────────────────

/// Config for the `GlobalEventBus` behind `GET /store-api/events`: lifecycle/
/// DDL events across the KV, JSON and relational engines. A section of its
/// own rather than an `[lsm]` extension, since the bus belongs to no engine.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Live broadcast channel capacity. A consumer that falls this far behind
    /// gets `event: reset` (`reason: "lagged"`) instead of a silent gap.
    pub channel_capacity: usize,
    /// Replay-ring size backing `Last-Event-ID` resume. `0` disables resume
    /// (every reconnect gets `reset`); `id:` fields are assigned regardless.
    pub replay_buffer_size: usize,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 256,
            replay_buffer_size: 1024,
        }
    }
}

// ── CORS (spec general/020) ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Enables the `CorsLayer`. `false` (default) = no layer in the stack,
    /// behavior unchanged.
    pub enabled: bool,
    /// Exact origins (`scheme://host[:port]`), byte-compared. `"*"` is
    /// allowed only as the sole entry — see `validate`.
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_origins: Vec::new(),
        }
    }
}

impl CorsConfig {
    /// Fail-fast startup check (spec general/020 §Start-Validierung). A
    /// no-op when `enabled = false` — `allowed_origins` is never read then.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(
            !self.allowed_origins.is_empty(),
            "invalid config: cors.enabled = true but cors.allowed_origins is empty — no origin would ever be allowed"
        );

        let has_wildcard = self.allowed_origins.iter().any(|o| o == "*");
        if has_wildcard {
            anyhow::ensure!(
                self.allowed_origins.iter().all(|o| o == "*"),
                "invalid config: cors.allowed_origins mixes the wildcard \"*\" with concrete origins — \"*\" must be the only entry"
            );
            return Ok(());
        }

        for origin in &self.allowed_origins {
            anyhow::ensure!(
                is_valid_origin_form(origin),
                "invalid config: cors.allowed_origins entry '{origin}' is not a valid origin — expected exactly scheme://host[:port] (lowercase, no userinfo/path/query/fragment)"
            );
            // Belt-and-suspenders: guarantees `cors::build_layer` can never
            // panic converting this entry to a `HeaderValue`. In practice
            // `is_valid_origin_form`'s charset is already ASCII-only, so this
            // never trips once the check above passed — it stays as the
            // documented, literal implementation of this rule.
            axum::http::HeaderValue::from_str(origin).map_err(|e| {
                anyhow::anyhow!("invalid config: cors.allowed_origins entry '{origin}' is not a valid header value: {e}")
            })?;
        }
        Ok(())
    }
}

/// Strict `scheme://host[:port]` shape (spec general/020 §Start-Validierung,
/// rules 3+5): scheme `[a-z][a-z0-9+.-]*`, non-empty lowercase host of
/// `[a-z0-9.-]`, optional numeric port, nothing else — no userinfo, path,
/// query, or fragment. The browser's `Origin` header always has exactly this
/// shape, and `AllowOrigin::list` compares byte-for-byte, so anything looser
/// here would silently never match.
fn is_valid_origin_form(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    let valid_scheme = match scheme_chars.next() {
        Some(first) if first.is_ascii_lowercase() => scheme_chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-')),
        _ => false,
    };
    if !valid_scheme || rest.is_empty() || rest.contains(['@', '/', '?', '#']) {
        return false;
    }

    let (host, port) = rest.rsplit_once(':').map_or((rest, None), |(h, p)| (h, Some(p)));
    if host.is_empty()
        || !host.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
    {
        return false;
    }
    match port {
        None => true,
        Some(p) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
    }
}

// ── Multicore (spec perf/017) ─────────────────────────────────────────────────

/// Sizing of the CPU offload pool behind `core::coop::offload`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MulticoreConfig {
    /// Permits for concurrent CPU offloads. `0` = auto = one per core beyond
    /// the request-path thread and one core of headroom.
    pub cpu_offload_threads: usize,
}

impl Default for MulticoreConfig {
    fn default() -> Self {
        Self { cpu_offload_threads: 0 }
    }
}

impl MulticoreConfig {
    /// Startup validation (spec general/030): more permits than `cores` would
    /// not bound the offload pool at all.
    pub fn validate(&self, cores: usize) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.cpu_offload_threads <= cores,
            "invalid config: multicore.cpu_offload_threads ({}) must be 0 (auto) or 1 to {cores} (available cores)",
            self.cpu_offload_threads
        );
        Ok(())
    }
}

// ── Key set (spec general/030) ────────────────────────────────────────────────

/// Every leaf key the server reads, e.g. `auth.admins.api_key`, taken from
/// the field lists serde passes while deserializing the config types.
pub(crate) fn known_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    LuraConfig::deserialize(KeyRecorder { path: String::new(), keys: &mut keys })
        .unwrap_or_else(|e| panic!("config key recorder: {e}"));
    keys
}

/// Appends the leaf key paths a TOML table sets. Elements of a table array
/// (`[[x]]`) share the path `x`; empty tables set no key. A segment with a
/// dot stays quoted, so it matches no known key.
fn toml_keys(table: &toml::Table, prefix: &str, keys: &mut Vec<String>) {
    for (name, value) in table {
        let segment = if name.contains('.') { format!("{name:?}") } else { name.clone() };
        let path = if prefix.is_empty() { segment } else { format!("{prefix}.{segment}") };
        match value {
            toml::Value::Table(table) => toml_keys(table, &path, keys),
            toml::Value::Array(items) if !items.is_empty() && items.iter().all(toml::Value::is_table) => {
                for item in items.iter().filter_map(toml::Value::as_table) {
                    toml_keys(item, &path, keys);
                }
            }
            _ => keys.push(path),
        }
    }
}

/// The `keys` that are not in `known`, sorted and deduplicated. A section
/// path counts as known: `admins = []` sets no key.
fn unknown_keys(keys: Vec<String>, known: &BTreeSet<String>) -> Vec<String> {
    let is_section = |key: &str| known.iter().any(|k| k.strip_prefix(key).is_some_and(|rest| rest.starts_with('.')));
    keys.into_iter()
        .filter(|key| !known.contains(key) && !is_section(key))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

type RecorderError = de::value::Error;

/// Deserializer that hands every struct its own field names, every `Option`
/// a value and every sequence one element, and records each leaf's path.
struct KeyRecorder<'a> {
    path: String,
    keys: &'a mut BTreeSet<String>,
}

impl KeyRecorder<'_> {
    fn record(self) {
        self.keys.insert(self.path);
    }
}

macro_rules! record_number {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.record();
            visitor.visit_u64(0)
        }
    )*};
}

impl<'de> Deserializer<'de> for KeyRecorder<'_> {
    type Error = RecorderError;

    // Types without a field list would drop their keys silently.
    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom(format!("cannot walk the type of '{}'", self.path)))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_map(FieldRecorder { path: self.path, keys: self.keys, fields: fields.iter(), field: "" })
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_some(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_seq(OneElement(Some(self)))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Some(&variant) = variants.first() else {
            return self.deserialize_any(visitor);
        };
        self.record();
        visitor.visit_enum(StrDeserializer::new(variant))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.record();
        visitor.visit_bool(false)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.record();
        visitor.visit_str("")
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    record_number! {
        deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64
        deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64
        deserialize_f32 deserialize_f64
    }

    serde::forward_to_deserialize_any! {
        i128 u128 char bytes byte_buf unit unit_struct newtype_struct tuple tuple_struct map identifier ignored_any
    }
}

/// A struct's fields as map entries; each value records under `path.field`.
struct FieldRecorder<'a> {
    path: String,
    keys: &'a mut BTreeSet<String>,
    fields: std::slice::Iter<'static, &'static str>,
    field: &'static str,
}

impl<'de> MapAccess<'de> for FieldRecorder<'_> {
    type Error = RecorderError;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error> {
        let Some(&field) = self.fields.next() else {
            return Ok(None);
        };
        self.field = field;
        seed.deserialize(StrDeserializer::new(field)).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Self::Error> {
        let path = match self.path.as_str() {
            "" => self.field.to_string(),
            parent => format!("{parent}.{}", self.field),
        };
        seed.deserialize(KeyRecorder { path, keys: &mut *self.keys })
    }
}

/// A sequence of one element, recorded under the sequence's own path.
struct OneElement<'a>(Option<KeyRecorder<'a>>);

impl<'de> SeqAccess<'de> for OneElement<'_> {
    type Error = RecorderError;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error> {
        self.0.take().map(|element| seed.deserialize(element)).transpose()
    }
}

/// Keys removed by spec general/030, for the tests that check their absence.
#[cfg(test)]
pub(crate) const REMOVED_KEYS: &[&str] = &[
    "server.unix_socket_mode",
    "log.modules.domains",
    "metrics.window_secs",
    "metrics.ticker_interval_ms",
    "io_engine.registered_buffer_count",
    "io_engine.registered_buffer_size",
    "io_engine.sqpoll_enabled",
    "io_engine.sqpoll_idle_ms",
    "io_engine.storage_thread_cpu",
    "io_engine.ring_depth",
    "io_engine.request_channel_capacity",
    "lsm.use_mmap",
    "block_cache.capacity_bytes",
    "block_cache.small_ratio",
    "block_cache.ghost_capacity",
    "json.lsm.use_mmap",
    "rel.lsm.use_mmap",
    "shm.state_size",
    "shm.command_buffer_size",
    "shm.segment_mode",
    "backup.scan_batch_size",
    "backup.scan_pause_ms",
    "json.max_document_key_length",
    "json.bulk_batch_size",
    "json.reindex_batch_size",
    "json.reindex_pause_ms",
    "json.purger_batch_size",
    "json.purger_interval_secs",
    "json.lsm.vlog_inline_threshold",
    "json.lsm.memtable_size_threshold",
    "json.lsm.flush_check_interval_ms",
    "json.lsm.compaction_check_interval_ms",
    "json.lsm.wal_event_channel_capacity",
    "json.lsm.watch_replay_buffer_size",
    "json.compaction.l0_threshold",
    "json.compaction.l1_max_size",
    "json.compaction.level_size_ratio",
    "json.compaction.max_sstable_size",
    "json.janitor.check_interval_secs",
    "json.janitor.dead_bytes_threshold",
    "json.janitor.min_vlog_size_bytes",
    "json.block_cache.capacity_bytes",
    "json.block_cache.small_ratio",
    "json.block_cache.ghost_capacity",
    "rel.max_columns",
    "rel.max_indexes_per_table",
    "rel.max_statement_len",
    "rel.max_text_len",
    "rel.default_limit",
    "rel.max_join_depth",
    "rel.max_response_bytes",
    "rel.cross_engine_sweep_interval_secs",
    "rel.cross_engine_sweep_batch_size",
    "rel.purger_batch_size",
    "rel.purger_interval_secs",
    "rel.lsm.vlog_inline_threshold",
    "rel.lsm.memtable_size_threshold",
    "rel.lsm.max_value_size",
    "rel.lsm.flush_check_interval_ms",
    "rel.lsm.compaction_check_interval_ms",
    "rel.lsm.wal_event_channel_capacity",
    "rel.lsm.watch_replay_buffer_size",
    "rel.compaction.l0_threshold",
    "rel.compaction.l1_max_size",
    "rel.compaction.level_size_ratio",
    "rel.compaction.max_sstable_size",
    "rel.janitor.check_interval_secs",
    "rel.janitor.dead_bytes_threshold",
    "rel.janitor.min_vlog_size_bytes",
    "rel.block_cache.capacity_bytes",
    "rel.block_cache.small_ratio",
    "rel.block_cache.ghost_capacity",
];

#[cfg(test)]
mod tests {
    use super::*;

    // Spec general/030: a config that still sets removed keys loads, and the
    // values have no effect.
    #[test]
    fn test_removed_keys_load_without_effect() {
        assert_eq!(REMOVED_KEYS.len(), 72, "the spec removes 72 keys");
        let toml_str: String = REMOVED_KEYS.iter().map(|key| format!("{key} = 1\n")).collect();
        let config: LuraConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::to_value(LuraConfig::default()).unwrap()
        );
    }

    #[test]
    fn test_multicore_defaults_and_toml_override() {
        assert_eq!(LuraConfig::default().multicore.cpu_offload_threads, 0);

        let toml_str = r#"
            [multicore]
            cpu_offload_threads = 6
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.multicore.cpu_offload_threads, 6);

        // Absent section stays at the default (`#[serde(default)]`).
        let config: LuraConfig = toml::from_str("[server]\nport = 1234\n").unwrap();
        assert_eq!(config.multicore.cpu_offload_threads, 0);
    }

    /// Asserts a startup error in the house format (spec general/030): it
    /// starts with `invalid config: <key> (<value>)` and names the allowed range.
    fn assert_invalid(result: anyhow::Result<()>, key_and_value: &str, allowed: &str) {
        let err = result.unwrap_err().to_string();
        assert!(err.starts_with(&format!("invalid config: {key_and_value}")), "{err}");
        assert!(err.contains(allowed), "{err}");
    }

    // Spec general/030 test 5: 0 (auto) and up to the core count are ok.
    #[test]
    fn test_multicore_validate_offload_threads_against_cores() {
        let config: LuraConfig = toml::from_str("[multicore]\ncpu_offload_threads = 0\n").unwrap();
        assert!(config.multicore.validate(8).is_ok());

        let config: LuraConfig = toml::from_str("[multicore]\ncpu_offload_threads = 8\n").unwrap();
        assert!(config.multicore.validate(8).is_ok());

        let config: LuraConfig = toml::from_str("[multicore]\ncpu_offload_threads = 9\n").unwrap();
        assert_invalid(config.multicore.validate(8), "multicore.cpu_offload_threads (9)", "1 to 8");
    }

    #[test]
    fn test_json_store_defaults() {
        let config = LuraConfig::default();
        assert!(config.json.enabled);
        assert_eq!(config.json.wal_path, "luradb_json.wal");
        assert_eq!(config.json.vlog_path, "luradb_json.vlog");
        assert_eq!(config.json.sstable_dir, "luradb_json_sstables");
    }

    #[test]
    fn test_json_store_toml_overrides() {
        let toml_str = r#"
            [json]
            enabled = false
            wal_path = "/data/json/wal.log"

            [json.lsm]
            max_value_size = 1048576
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.json.enabled);
        assert_eq!(config.json.wal_path, "/data/json/wal.log");
        assert_eq!(config.json.lsm.max_value_size, 1024 * 1024);
        assert_eq!(config.json.lsm.max_key_length, 256);
        assert_eq!(config.json.vlog_path, "luradb_json.vlog");
    }

    #[test]
    fn test_json_path_collisions_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();

        // JSON path colliding with a KV path.
        let mut config = LuraConfig::default();
        config.json.sstable_dir = config.storage.sstable_dir.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());

        // Two JSON paths colliding with each other.
        let mut config = LuraConfig::default();
        config.json.vlog_path = config.json.wal_path.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());

        // Trailing slash must not mask a collision.
        let mut config = LuraConfig::default();
        config.json.sstable_dir = "luradb_sstables/".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_rel_store_defaults() {
        let config = LuraConfig::default();
        assert!(config.rel.enabled);
        assert_eq!(config.rel.wal_path, "luradb_rel.wal");
        assert_eq!(config.rel.vlog_path, "luradb_rel.vlog");
        assert_eq!(config.rel.sstable_dir, "luradb_rel_sstables");
    }

    #[test]
    fn test_rel_store_toml_overrides() {
        let toml_str = r#"
            [rel]
            enabled = false
            wal_path = "/data/rel/wal.log"

            [rel.lsm]
            max_key_length = 128
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.rel.enabled);
        assert_eq!(config.rel.wal_path, "/data/rel/wal.log");
        assert_eq!(config.rel.lsm.max_key_length, 128);
        assert_eq!(config.rel.vlog_path, "luradb_rel.vlog");
    }

    #[test]
    fn test_rel_path_collisions_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();

        // rel path colliding with a KV path.
        let mut config = LuraConfig::default();
        config.rel.sstable_dir = config.storage.sstable_dir.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());

        // rel path colliding with a JSON path.
        let mut config = LuraConfig::default();
        config.rel.wal_path = config.json.wal_path.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());

        // Two rel paths colliding with each other.
        let mut config = LuraConfig::default();
        config.rel.vlog_path = config.rel.wal_path.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());

        // Trailing slash must not mask a collision.
        let mut config = LuraConfig::default();
        config.rel.sstable_dir = "luradb_sstables/".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_uds_config_parsing() {
        let toml_str = r#"
            [server]
            unix_socket_path = "/run/luradb/luradb.sock"

            [auth]
            trusted_uids = [0, 1000]
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.unix_socket_path.as_deref(), Some("/run/luradb/luradb.sock"));
        assert_eq!(config.auth.trusted_uids, vec![0, 1000]);
    }

    #[test]
    fn test_uds_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(config.server.unix_socket_path.is_none());
        assert!(config.auth.trusted_uids.is_empty());
    }

    #[test]
    fn test_tls_defaults() {
        let config = LuraConfig::default();
        assert!(config.server.http_enabled);
        assert!(!config.server.tls_enabled);
        assert_eq!(config.server.tls_port, 3443);
        assert_eq!(config.server.tls_cert_path, "/etc/luradb/tls/server.crt");
        assert_eq!(config.server.tls_key_path, "/etc/luradb/tls/server.key");
    }

    // An old config predating spec general/011 has no [server] tls_* or
    // http_enabled keys — it must still parse, with the new keys defaulted.
    #[test]
    fn test_tls_old_config_without_new_keys_parses_with_defaults() {
        let toml_str = r#"
            [server]
            bind_address = "127.0.0.1"
            port = 3000
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.server.http_enabled);
        assert!(!config.server.tls_enabled);
        assert_eq!(config.server.tls_port, 3443);
    }

    #[test]
    fn test_tls_toml_overrides() {
        let toml_str = r#"
            [server]
            http_enabled = false
            tls_enabled = true
            tls_port = 8443
            tls_cert_path = "/tmp/server.crt"
            tls_key_path = "/tmp/server.key"
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.server.http_enabled);
        assert!(config.server.tls_enabled);
        assert_eq!(config.server.tls_port, 8443);
        assert_eq!(config.server.tls_cert_path, "/tmp/server.crt");
        assert_eq!(config.server.tls_key_path, "/tmp/server.key");
    }

    #[test]
    fn test_server_validate_default_ok() {
        assert!(ServerConfig::default().validate().is_ok());
    }

    // Spec general/014 test 5: prod-safe default — docs routes stay off
    // unless explicitly enabled.
    #[test]
    fn test_swagger_disabled_by_default() {
        assert!(!ServerConfig::default().swagger_enabled);
    }

    #[test]
    fn test_server_validate_rejects_both_listeners_disabled() {
        let mut server = ServerConfig::default();
        server.http_enabled = false;
        server.tls_enabled = false;
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_server_validate_rejects_port_collision() {
        let mut server = ServerConfig::default();
        server.tls_enabled = true;
        server.tls_port = server.port;
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_io_engine_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(!config.io_engine.enabled);
    }

    #[test]
    fn test_io_engine_toml_overrides() {
        let toml_str = r#"
            [io_engine]
            enabled = true
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.io_engine.enabled);
    }

    #[test]
    fn test_shm_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(!config.shm.enabled);
        assert_eq!(config.shm.instance_id, "0");
        assert_eq!(config.shm.data_buffer_size, 268_435_456);
    }

    #[test]
    fn test_shm_toml_overrides() {
        let toml_str = r#"
            [shm]
            enabled = true
            instance_id = "test"
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.shm.enabled);
        assert_eq!(config.shm.instance_id, "test");
        assert_eq!(config.shm.data_buffer_size, 268_435_456); // untouched default
    }

    #[test]
    fn test_shm_registration_socket_path_default_and_resolve() {
        let mut config = ShmConfig::default();
        assert_eq!(config.registration_socket_path, "/run/luradb/{instance_id}.sock");
        config.instance_id = "prod-2".to_string();
        assert_eq!(config.resolved_registration_socket_path(), "/run/luradb/prod-2.sock");
    }

    #[test]
    fn test_shm_data_size_and_snapshot_interval_minimums() {
        let mut config = ShmConfig::default();
        config.data_buffer_size = 100;
        assert_invalid(config.validate(), "shm.data_buffer_size (100)", "at least 4096");

        config.data_buffer_size = 8192;
        config.snapshot_interval_ms = 0;
        assert_invalid(config.validate(), "shm.snapshot_interval_ms (0)", "at least 1");
    }

    #[test]
    fn test_shm_instance_id_charset() {
        let mut config = ShmConfig::default();
        config.instance_id = "0_backup".to_string();
        assert_invalid(config.validate(), "shm.instance_id ('0_backup')", "[A-Za-z0-9-]");

        config.instance_id = String::new();
        assert_invalid(config.validate(), "shm.instance_id ('')", "non-empty");

        config.instance_id = "prod-2".to_string();
        assert!(config.validate().is_ok());
    }

    // Spec general/030 test 5: with SHM on, the resolved registration socket
    // must not take the REST socket's path. The packaged REST socket collides
    // with the default template for instance "luradb".
    #[test]
    fn test_shm_validate_registration_socket_against_rest_socket() {
        let toml_str = r#"
            [server]
            unix_socket_path = "/run/luradb/luradb.sock"

            [shm]
            enabled = true
            instance_id = "luradb"
        "#;
        let mut config: LuraConfig = toml::from_str(toml_str).unwrap();
        let err = config.shm.validate_registration_socket(&config.server).unwrap_err().to_string();
        assert!(err.starts_with("invalid config: shm.registration_socket_path ('/run/luradb/luradb.sock')"), "{err}");
        assert!(err.contains("server.unix_socket_path"), "{err}");

        // Compared per path component, so another spelling still collides.
        config.server.unix_socket_path = Some("/run/luradb//luradb.sock".to_string());
        assert!(config.shm.validate_registration_socket(&config.server).is_err());

        config.shm.enabled = false;
        assert!(config.shm.validate_registration_socket(&config.server).is_ok());

        config.shm.enabled = true;
        config.shm.instance_id = "0".to_string();
        assert!(config.shm.validate_registration_socket(&config.server).is_ok());

        config.shm.instance_id = "luradb".to_string();
        config.server.unix_socket_path = None;
        assert!(config.shm.validate_registration_socket(&config.server).is_ok());
    }

    #[test]
    fn test_resolve_config_path_cli_arg_always_wins() {
        let cli_path = PathBuf::from("/custom/path.toml");
        // Even if nothing exists, an explicit --config is used verbatim.
        let resolved = resolve_config_path(Some(cli_path.clone()), |_| false);
        assert_eq!(resolved, cli_path);
    }

    #[test]
    fn test_resolve_config_path_prefers_dev_default() {
        let resolved = resolve_config_path(None, |p| p == Path::new("luradb.toml"));
        assert_eq!(resolved, PathBuf::from("luradb.toml"));
    }

    #[test]
    fn test_resolve_config_path_falls_back_to_installed() {
        let resolved = resolve_config_path(None, |p| p == Path::new("/etc/luradb/luradb.toml"));
        assert_eq!(resolved, PathBuf::from("/etc/luradb/luradb.toml"));
    }

    #[test]
    fn test_resolve_config_path_defaults_when_nothing_exists() {
        let resolved = resolve_config_path(None, |_| false);
        assert_eq!(resolved, PathBuf::from("luradb.toml"));
    }

    #[test]
    fn test_resolve_config_path_dev_default_checked_before_installed() {
        // Both exist: ./luradb.toml (dev workflow) must win over /etc.
        let resolved = resolve_config_path(None, |_| true);
        assert_eq!(resolved, PathBuf::from("luradb.toml"));
    }

    // ── Backup & Restore ────────────────────────────────────────────────────

    #[test]
    fn test_backup_defaults() {
        let config = LuraConfig::default();
        assert!(!config.backup.enabled);
        assert_eq!(config.backup.dir, "luradb_backups");
        assert!(config.backup.schedule.is_empty());
    }

    #[test]
    fn test_backup_toml_example_from_spec_parses() {
        let toml_str = r#"
            [backup]
            enabled = false
            dir = "luradb_backups"

            [[backup.schedule]]
            name = "nightly-all"
            cron = "0 3 * * *"
            scope = "all"
            include_auth = false
            keep_last = 7
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.backup.enabled);
        assert_eq!(config.backup.schedule.len(), 1);
        let sched = &config.backup.schedule[0];
        assert_eq!(sched.name, "nightly-all");
        assert_eq!(sched.cron, "0 3 * * *");
        assert_eq!(sched.scope, "all");
        assert!(!sched.include_auth);
        assert_eq!(sched.keep_last, 7);
    }

    #[test]
    fn test_backup_schedule_include_auth_defaults_false() {
        let toml_str = r#"
            [[backup.schedule]]
            name = "s1"
            cron = "0 3 * * *"
            scope = "all"
            keep_last = 3
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.backup.schedule[0].include_auth);
    }

    fn valid_backup_schedule(name: &str) -> BackupScheduleConfig {
        BackupScheduleConfig {
            name: name.to_string(),
            cron: "0 3 * * *".to_string(),
            scope: "all".to_string(),
            include_auth: false,
            keep_last: 7,
        }
    }

    #[test]
    fn test_backup_validate_disabled_skips_all_checks() {
        let mut config = LuraConfig::default();
        // Every field below would fail validation if checked — enabled=false
        // must short-circuit before any of them are looked at.
        config.backup.dir = String::new();
        config.backup.schedule.push(BackupScheduleConfig {
            name: String::new(),
            cron: "not a cron".to_string(),
            scope: "not a scope".to_string(),
            include_auth: false,
            keep_last: 0,
        });
        assert!(config.backup.validate().is_ok());
    }

    #[test]
    fn test_backup_validate_enabled_with_valid_config_ok() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.schedule.push(valid_backup_schedule("nightly-all"));
        assert!(config.backup.validate().is_ok());
    }

    #[test]
    fn test_backup_validate_rejects_empty_dir() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.dir = String::new();
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_validate_data_paths_backup_dir_equal_to_json_or_rel_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();

        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.dir = config.json.sstable_dir.clone();
        let err = config.validate_data_paths(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("backup.dir") && err.contains("json.sstable_dir"), "{err}");

        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.dir = config.rel.sstable_dir.clone();
        let err = config.validate_data_paths(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("backup.dir") && err.contains("rel.sstable_dir"), "{err}");
    }

    #[test]
    fn test_validate_data_paths_backup_enabled_default_dir_ok() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        assert!(config.validate_data_paths(tmp.path()).is_ok());
    }

    #[test]
    fn test_backup_validate_rejects_invalid_cron() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.cron = "not a cron".to_string();
        config.backup.schedule.push(sched);
        assert_invalid(config.backup.validate(), "backup.schedule.cron ('not a cron')", "(schedule 's1')");
    }

    // Spec general/030 test 5: a schedule without a date within 4 years of
    // the start is a startup error. 29 February next fires 1461 days minus a
    // minute after 2024-02-29T00:01Z, but not within 4 years of
    // 2096-02-29T00:01Z (2100 is no leap year).
    #[test]
    fn test_backup_validate_rejects_cron_without_date_within_four_years() {
        const LEAP_DAY_2024_AT_0001: u64 = 1_709_164_860;
        const LEAP_DAY_2096_AT_0001: u64 = 3_981_312_060;
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("feb-31");
        sched.cron = "0 0 31 2 *".to_string();
        config.backup.schedule.push(sched);
        let err = config.backup.validate_at(LEAP_DAY_2024_AT_0001).unwrap_err().to_string();
        assert!(err.starts_with("invalid config: backup.schedule.cron ('0 0 31 2 *')"), "{err}");
        assert!(err.contains("4 years") && err.ends_with("(schedule 'feb-31')"), "{err}");

        config.backup.schedule[0].cron = "0 0 29 2 *".to_string();
        assert!(config.backup.validate_at(LEAP_DAY_2024_AT_0001).is_ok());
        assert!(config.backup.validate_at(LEAP_DAY_2096_AT_0001).is_err());

        config.backup.enabled = false;
        config.backup.schedule[0].cron = "0 0 31 2 *".to_string();
        assert!(config.backup.validate_at(LEAP_DAY_2024_AT_0001).is_ok());
    }

    #[test]
    fn test_backup_validate_rejects_invalid_scope() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.scope = "not-a-scope".to_string();
        config.backup.schedule.push(sched);
        assert_invalid(config.backup.validate(), "backup.schedule.scope ('not-a-scope')", "(schedule 's1')");
    }

    #[test]
    fn test_backup_validate_rejects_keep_last_zero() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.keep_last = 0;
        config.backup.schedule.push(sched);
        assert_invalid(config.backup.validate(), "backup.schedule.keep_last (0)", "at least 1 (schedule 's1')");
    }

    #[test]
    fn test_backup_validate_rejects_duplicate_schedule_names() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.schedule.push(valid_backup_schedule("dup"));
        config.backup.schedule.push(valid_backup_schedule("dup"));
        assert_invalid(config.backup.validate(), "backup.schedule.name ('dup')", "unique");
    }

    #[test]
    fn test_backup_validate_rejects_invalid_schedule_name_characters() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.name = "bad name!".to_string();
        config.backup.schedule.push(sched);
        assert_invalid(config.backup.validate(), "backup.schedule.name ('bad name!')", "1-50 characters");
    }

    #[test]
    fn test_backup_validate_rejects_schedule_name_too_long() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let name = "a".repeat(51);
        config.backup.schedule.push(valid_backup_schedule(&name));
        assert_invalid(config.backup.validate(), &format!("backup.schedule.name ('{name}')"), "1-50 characters");
    }

    // ── Log HTTP access (spec general/005) ──────────────────────────────────

    #[test]
    fn test_log_http_access_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(!config.log.http_access);
    }

    // Spec test 2: http_access=true + path="" -> validate() fails.
    #[test]
    fn test_log_validate_rejects_http_access_without_path() {
        let mut log = LogConfig::default();
        log.http_access = true;
        log.path = String::new();
        assert!(log.validate().is_err());
    }

    #[test]
    fn test_log_validate_accepts_http_access_with_path() {
        let mut log = LogConfig::default();
        log.http_access = true;
        log.path = "/var/log/luradb".to_string();
        assert!(log.validate().is_ok());
    }

    #[test]
    fn test_log_validate_disabled_ignores_empty_path() {
        let log = LogConfig::default();
        assert!(log.validate().is_ok());
    }

    // ── Auth fail-closed (spec general/013) ─────────────────────────────────

    #[test]
    fn test_server_default_bind_address_is_loopback() {
        assert_eq!(ServerConfig::default().bind_address, "127.0.0.1");
    }

    #[test]
    fn test_auth_validate_rejects_disabled_auth_on_all_interfaces_ipv4() {
        let mut server = ServerConfig::default();
        server.bind_address = "0.0.0.0".to_string();
        assert!(AuthConfig::default().validate(&server).is_err());
    }

    #[test]
    fn test_auth_validate_rejects_disabled_auth_on_all_interfaces_ipv6() {
        let mut server = ServerConfig::default();
        server.bind_address = "::".to_string();
        assert!(AuthConfig::default().validate(&server).is_err());
    }

    #[test]
    fn test_auth_validate_accepts_disabled_auth_on_loopback_ipv4() {
        let mut server = ServerConfig::default();
        server.bind_address = "127.0.0.1".to_string();
        assert!(AuthConfig::default().validate(&server).is_ok());
    }

    #[test]
    fn test_auth_validate_accepts_disabled_auth_on_loopback_ipv6() {
        let mut server = ServerConfig::default();
        server.bind_address = "::1".to_string();
        assert!(AuthConfig::default().validate(&server).is_ok());
    }

    #[test]
    fn test_auth_validate_accepts_enabled_auth_on_all_interfaces() {
        let mut server = ServerConfig::default();
        server.bind_address = "0.0.0.0".to_string();
        let auth = AuthConfig { enabled: true, ..AuthConfig::default() };
        assert!(auth.validate(&server).is_ok());
    }

    #[test]
    fn test_auth_validate_rejects_unparseable_bind_address() {
        let mut server = ServerConfig::default();
        server.bind_address = "not-an-ip".to_string();
        assert!(AuthConfig::default().validate(&server).is_err());
    }

    // The address is parsed unconditionally, independent of whether the
    // loopback rule itself would apply — an unparseable address never binds.
    #[test]
    fn test_auth_validate_rejects_unparseable_bind_address_even_when_enabled() {
        let mut server = ServerConfig::default();
        server.bind_address = "not-an-ip".to_string();
        let auth = AuthConfig { enabled: true, ..AuthConfig::default() };
        assert!(auth.validate(&server).is_err());
    }

    // A config file without an [auth] section must not bypass the check:
    // serde fills in AuthConfig::default() (enabled = false), and validate()
    // still fails once bound beyond loopback.
    #[test]
    fn test_auth_validate_missing_auth_section_still_fails_closed() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0"
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.auth.enabled);
        assert!(config.auth.validate(&config.server).is_err());
    }

    // ── Global event stream (spec general/018) ──────────────────────────────

    #[test]
    fn test_events_defaults() {
        let config = LuraConfig::default();
        assert_eq!(config.events.channel_capacity, 256);
        assert_eq!(config.events.replay_buffer_size, 1024);
    }

    #[test]
    fn test_events_toml_overrides() {
        let toml_str = r#"
            [events]
            channel_capacity = 8
            replay_buffer_size = 0
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.events.channel_capacity, 8);
        assert_eq!(config.events.replay_buffer_size, 0);
    }

    #[test]
    fn test_auth_validate_missing_auth_section_loopback_ok() {
        let toml_str = r#"
            [server]
            bind_address = "127.0.0.1"
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.auth.enabled);
        assert!(config.auth.validate(&config.server).is_ok());
    }

    // ── CORS (spec general/020) ──────────────────────────────────────────────

    #[test]
    fn test_cors_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(!config.cors.enabled);
        assert!(config.cors.allowed_origins.is_empty());
    }

    #[test]
    fn test_cors_toml_overrides() {
        let toml_str = r#"
            [cors]
            enabled = true
            allowed_origins = ["https://console.example.com", "http://localhost:5173"]
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.cors.enabled);
        assert_eq!(
            config.cors.allowed_origins,
            vec!["https://console.example.com".to_string(), "http://localhost:5173".to_string()]
        );
    }

    #[test]
    fn test_cors_validate_disabled_skips_all_checks() {
        let mut cors = CorsConfig::default();
        // Would fail every check below if looked at — enabled=false must
        // short-circuit before any of it.
        cors.allowed_origins = vec!["not a valid origin at all".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_rejects_enabled_with_empty_origins() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_wildcard_mixed_with_concrete_origin() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["*".to_string(), "https://example.com".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_accepts_wildcard_alone() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["*".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_accepts_wildcard_duplicated() {
        // Duplicate "*" entries are still "only the wildcard", not "mixed
        // with concrete origins".
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["*".to_string(), "*".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_accepts_origin_with_port() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["http://localhost:5173".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_accepts_origin_without_port() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://console.example.com".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_accepts_duplicate_origin() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins =
            vec!["https://console.example.com".to_string(), "https://console.example.com".to_string()];
        assert!(cors.validate().is_ok());
    }

    #[test]
    fn test_cors_validate_rejects_trailing_slash() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://console.example.com/".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_missing_scheme() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["console.example.com".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_userinfo() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://user:pw@console.example.com".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_query() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://console.example.com?x=1".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_fragment() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://console.example.com#f".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_empty_host() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_uppercase_host() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://Console.example.com".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_cors_validate_rejects_unparseable_header_value() {
        let mut cors = CorsConfig::default();
        cors.enabled = true;
        cors.allowed_origins = vec!["https://exa\nmple.com".to_string()];
        assert!(cors.validate().is_err());
    }

    #[test]
    fn test_lsm_validate_default_ok() {
        let config = LuraConfig::default();
        assert!(config.lsm.validate().is_ok());
        assert!(config.json.lsm.validate().is_ok());
        assert!(config.rel.lsm.validate().is_ok());
    }

    #[test]
    fn test_lsm_validate_max_value_size_at_cap_ok() {
        let mut lsm = LsmConfig::default();
        lsm.max_value_size = WAL_MAX_FIELD_LEN;
        assert!(lsm.validate().is_ok());
    }

    #[test]
    fn test_lsm_validate_max_value_size_over_cap_rejected() {
        let mut lsm = LsmConfig::default();
        lsm.max_value_size = WAL_MAX_FIELD_LEN + 1;
        let err = lsm.validate().unwrap_err().to_string();
        assert!(err.contains("lsm.max_value_size"), "{err}");
        assert!(err.contains(&(WAL_MAX_FIELD_LEN + 1).to_string()), "{err}");
        assert!(err.contains(&WAL_MAX_FIELD_LEN.to_string()), "{err}");
    }

    #[test]
    fn test_lsm_validate_max_key_length_over_cap_rejected() {
        let mut lsm = LsmConfig::default();
        lsm.max_key_length = WAL_MAX_FIELD_LEN + 1;
        let err = lsm.validate().unwrap_err().to_string();
        assert!(err.contains("lsm.max_key_length"), "{err}");
    }

    #[test]
    fn test_lsm_validate_json_lsm_over_cap_rejected() {
        let mut config = LuraConfig::default();
        config.json.lsm.max_value_size = WAL_MAX_FIELD_LEN + 1;
        let err = config.json.lsm.validate().unwrap_err().to_string();
        assert!(err.contains("json.lsm.max_value_size"), "{err}");
        assert!(err.contains(&(WAL_MAX_FIELD_LEN + 1).to_string()), "{err}");

        let mut config = LuraConfig::default();
        config.json.lsm.max_key_length = WAL_MAX_FIELD_LEN + 1;
        let err = config.json.lsm.validate().unwrap_err().to_string();
        assert!(err.contains("json.lsm.max_key_length"), "{err}");
    }

    #[test]
    fn test_lsm_validate_rel_lsm_over_cap_rejected() {
        let mut config = LuraConfig::default();
        config.rel.lsm.max_key_length = WAL_MAX_FIELD_LEN + 1;
        let err = config.rel.lsm.validate().unwrap_err().to_string();
        assert!(err.contains("rel.lsm.max_key_length"), "{err}");
        assert!(err.contains(&(WAL_MAX_FIELD_LEN + 1).to_string()), "{err}");
    }

    // ── Data path collisions via real locations (spec general/031) ──────────

    #[test]
    fn test_validate_data_paths_dot_segment_collision() {
        // Test 1: `x` and `./x` resolve to the same location.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.storage.wal_path = "x".to_string();
        config.storage.vlog_path = "./x".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_relative_vs_absolute_in_base_collision() {
        // Test 2: a relative path and the same location spelled absolute.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.storage.wal_path = "y".to_string();
        config.storage.sstable_dir = tmp.path().join("y").to_str().unwrap().to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_symlink_directory_collision() {
        // Test 3: a symlinked directory pointing at another data directory.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        std::fs::create_dir(tmp.path().join(&config.storage.sstable_dir)).unwrap();
        std::os::unix::fs::symlink(&config.storage.sstable_dir, tmp.path().join("link")).unwrap();

        config.json.sstable_dir = "link".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_wal_collides_with_vlog_generation_file() {
        // Test 4: `json.wal_path` equal to `<storage.vlog_path>.1`.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.json.wal_path = format!("{}.1", config.storage.vlog_path);
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_storage_wal_equals_vlog_rejected() {
        // Test 5: `storage.wal_path` equal to `storage.vlog_path`.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.storage.wal_path = config.storage.vlog_path.clone();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_backup_dir_collides_with_storage_different_spelling() {
        // Test 6: `backup.dir` equal to a data directory in another spelling.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.dir = format!("./{}", config.storage.sstable_dir);
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_distinct_paths_some_nonexistent_ok() {
        // Test 7: distinct paths, some existing, some not yet.
        let tmp = tempfile::TempDir::new().unwrap();
        let config = LuraConfig::default();
        std::fs::create_dir(tmp.path().join(&config.storage.sstable_dir)).unwrap();
        std::fs::write(tmp.path().join(&config.storage.wal_path), b"").unwrap();
        assert!(config.validate_data_paths(tmp.path()).is_ok());
    }

    #[test]
    fn test_validate_data_paths_disabled_json_with_paths_equal_to_kv_ok() {
        // Test 8: a disabled engine's paths are not checked.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        config.json.enabled = false;
        config.json.wal_path = config.storage.wal_path.clone();
        config.json.vlog_path = config.storage.vlog_path.clone();
        config.json.sstable_dir = config.storage.sstable_dir.clone();
        assert!(config.validate_data_paths(tmp.path()).is_ok());
    }

    #[test]
    fn test_validate_data_paths_error_message_names_both_keys_and_location() {
        // Test 9: both keys and the resolved location, behind a symlinked base.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", tmp.path().join("alias")).unwrap();

        let mut config = LuraConfig::default();
        config.storage.wal_path = config.storage.vlog_path.clone();
        let err = config.validate_data_paths(&tmp.path().join("alias")).unwrap_err().to_string();
        assert!(err.contains("storage.wal_path"), "{err}");
        assert!(err.contains("storage.vlog_path"), "{err}");
        let location = std::fs::canonicalize(tmp.path()).unwrap().join("real").join(&config.storage.vlog_path);
        assert!(err.contains(&format!("'{}'", location.display())), "{err}");
    }

    #[test]
    fn test_validate_data_paths_dangling_symlink_target_detected() {
        // The engines' O_CREAT would create a dangling symlink's target.
        let tmp = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink("nowhere", tmp.path().join("link")).unwrap();

        let mut config = LuraConfig::default();
        config.storage.wal_path = "link".to_string();
        config.storage.vlog_path = "nowhere".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_dotdot_after_symlink_uses_target_parent() {
        // Like the kernel: `..` after a symlink acts on its target.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("nested")).unwrap();
        std::fs::create_dir(tmp.path().join("nested/dirA")).unwrap();
        std::os::unix::fs::symlink("nested/dirA", tmp.path().join("link")).unwrap();

        let mut config = LuraConfig::default();
        config.storage.wal_path = "link/../x".to_string();
        config.storage.vlog_path = "nested/x".to_string();
        assert!(config.validate_data_paths(tmp.path()).is_err());
    }

    #[test]
    fn test_validate_data_paths_symlink_named_like_vlog_generation_rejected() {
        // Rule 2 via the slot: the target misses the pattern, the link's own name hits it.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = LuraConfig::default();
        let generation_name = format!("{}.2", config.storage.vlog_path);
        std::os::unix::fs::symlink("elsewhere", tmp.path().join(&generation_name)).unwrap();

        config.json.wal_path = generation_name;
        let err = config.validate_data_paths(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("storage.vlog_path") && err.contains("json.wal_path"), "{err}");
    }

    #[test]
    fn test_validate_data_paths_symlink_loop_error_names_key() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink("loop", tmp.path().join("loop")).unwrap();

        let mut config = LuraConfig::default();
        config.storage.wal_path = "loop".to_string();
        let err = config.validate_data_paths(tmp.path()).unwrap_err().to_string();
        assert!(err.starts_with("invalid config: storage.wal_path "), "{err}");
        assert!(err.contains("symlink hops"), "{err}");
    }

    // ── Startup checks of the remaining keys (spec general/030) ─────────────

    // Test 5; runs even with the JSON engine disabled (general/025 pattern).
    #[test]
    fn test_json_validate_bulk_body_limit() {
        let config: LuraConfig = toml::from_str("[json]\nenabled = false\nbulk_body_limit_bytes = 0\n").unwrap();
        assert_invalid(config.json.validate(), "json.bulk_body_limit_bytes (0)", "at least 1");

        let config: LuraConfig = toml::from_str("[json]\nbulk_body_limit_bytes = 1\n").unwrap();
        assert!(config.json.validate().is_ok());
    }

    // Test 5: table and index ids are u32, so 2^32 - 1 is the upper bound.
    #[test]
    fn test_rel_validate_max_tables_per_domain() {
        let parse = |value: u64| -> LuraConfig {
            toml::from_str(&format!("[rel]\nenabled = false\nmax_tables_per_domain = {value}\n")).unwrap()
        };
        assert_invalid(parse(0).rel.validate(), "rel.max_tables_per_domain (0)", "between 1 and 4294967295");
        assert!(parse(1).rel.validate().is_ok());
        assert!(parse(4_294_967_295).rel.validate().is_ok());
        assert_invalid(
            parse(4_294_967_296).rel.validate(),
            "rel.max_tables_per_domain (4294967296)",
            "between 1 and 4294967295",
        );
    }

    // Test 5.
    #[test]
    fn test_rel_validate_max_limit_and_max_sort_rows() {
        let mut rel = RelStoreConfig::default();
        rel.max_limit = 0;
        assert_invalid(rel.validate(), "rel.max_limit (0)", "at least 1");
        rel.max_limit = 1;
        assert!(rel.validate().is_ok());

        rel.max_sort_rows = 0;
        assert_invalid(rel.validate(), "rel.max_sort_rows (0)", "at least 1");
        rel.max_sort_rows = 1;
        assert!(rel.validate().is_ok());
    }

    // Test 5: the row needs room beyond its fixed 4-byte header, and the
    // storage value limit (at least max_row_size) must fit the WAL field cap.
    #[test]
    fn test_rel_validate_max_row_size() {
        let mut rel = RelStoreConfig::default();
        rel.max_row_size = 4;
        assert_invalid(rel.validate(), "rel.max_row_size (4)", "at least 5");
        rel.max_row_size = 5;
        assert!(rel.validate().is_ok());
        rel.max_row_size = WAL_MAX_FIELD_LEN;
        assert!(rel.validate().is_ok());
        rel.max_row_size = WAL_MAX_FIELD_LEN + 1;
        assert_invalid(
            rel.validate(),
            &format!("rel.max_row_size ({})", WAL_MAX_FIELD_LEN + 1),
            &WAL_MAX_FIELD_LEN.to_string(),
        );
    }

    // Test 6: one byte below the lower bounds is a startup error, the bounds
    // themselves and the WAL field cap are accepted.
    #[test]
    fn test_json_and_rel_lsm_lower_bounds() {
        let parse = |toml: &str| -> LuraConfig { toml::from_str(toml).unwrap() };

        let config = parse("[json.lsm]\nmax_key_length = 68\n");
        assert_invalid(config.json.validate(), "json.lsm.max_key_length (68)", "at least 69");
        assert!(parse("[json.lsm]\nmax_key_length = 69\n").json.validate().is_ok());
        assert!(parse(&format!("[json.lsm]\nmax_key_length = {WAL_MAX_FIELD_LEN}\n")).json.validate().is_ok());

        let config = parse("[json.lsm]\nmax_value_size = 4095\n");
        assert_invalid(config.json.validate(), "json.lsm.max_value_size (4095)", "at least 4096");
        assert!(parse("[json.lsm]\nmax_value_size = 4096\n").json.validate().is_ok());

        let config = parse("[rel.lsm]\nmax_key_length = 72\n");
        assert_invalid(config.rel.validate(), "rel.lsm.max_key_length (72)", "at least 73");
        assert!(parse("[rel.lsm]\nmax_key_length = 73\n").rel.validate().is_ok());
        assert!(parse(&format!("[rel.lsm]\nmax_key_length = {WAL_MAX_FIELD_LEN}\n")).rel.validate().is_ok());
    }

    // ── Key set, unknown keys and config-file gate (spec general/030) ───────

    // Test 3: optional fields and list elements count, section paths and
    // removed keys do not.
    #[test]
    fn test_known_keys_include_optional_fields_and_list_elements() {
        let keys = known_keys();
        for key in [
            "log.path",
            "backup.schedule.cron",
            "auth.admins.api_key",
            "auth.trusted_uids",
            "server.unix_socket_path",
            "log.modules.auth",
            "log.level",
            "json.lsm.max_value_size",
        ] {
            assert!(keys.contains(key), "{key} missing from {keys:?}");
        }
        for section in ["server", "auth.admins", "log.modules", "json.lsm", "backup.schedule"] {
            assert!(!keys.contains(section), "section path {section} in {keys:?}");
        }
        for removed in REMOVED_KEYS {
            assert!(!keys.contains(*removed), "removed key {removed} in {keys:?}");
        }
    }

    // Test 4: the config still loads; the detection names the key.
    #[test]
    fn test_parse_reports_unknown_key() {
        let (config, unknown) = LuraConfig::parse("[metrics]\nwindow_secs = 60\n[server]\nport = 4000\n").unwrap();
        assert_eq!(config.server.port, 4000);
        assert_eq!(unknown, ["metrics.window_secs"]);

        let (_, unknown) = LuraConfig::parse("[server]\nport = 4000\n").unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
    }

    // Story 6: every removed key is reported after an update.
    #[test]
    fn test_parse_reports_every_removed_key() {
        let toml_str: String = REMOVED_KEYS.iter().map(|key| format!("{key} = 1\n")).collect();
        let (_, unknown) = LuraConfig::parse(&toml_str).unwrap();
        let mut expected: Vec<&str> = REMOVED_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(unknown, expected);
    }

    // Array-of-tables elements share one path, each key is reported once,
    // and neither an empty table nor an empty table array sets a key.
    #[test]
    fn test_parse_unknown_keys_in_table_arrays_and_empty_tables() {
        let toml_str = r#"
[auth]
admins = []

[[backup.schedule]]
name = "a"
cron = "0 3 * * *"
scope = "all"
keep_last = 1
retention = 1

[[backup.schedule]]
name = "b"
cron = "0 4 * * *"
scope = "all"
keep_last = 1
retention = 1

[json.compaction]

[[stale]]
flag = true
"#;
        let (_, unknown) = LuraConfig::parse(toml_str).unwrap();
        assert_eq!(unknown, ["backup.schedule.retention", "stale.flag"]);
    }

    // A quoted segment with a dot matches no field, so serde ignores it.
    #[test]
    fn test_parse_reports_quoted_keys_with_dots() {
        let toml_str = r#"
"server.port" = 4000

[auth]
"admins.name" = "x"
"#;
        let (config, unknown) = LuraConfig::parse(toml_str).unwrap();
        assert_eq!(config.server.port, LuraConfig::default().server.port);
        assert_eq!(unknown, [r#""server.port""#, r#"auth."admins.name""#]);
    }

    /// What the config-file gate finds (spec general/030).
    #[derive(Debug, Default, PartialEq)]
    struct GateFindings {
        /// Known keys absent from the shipped config.
        missing: Vec<String>,
        /// Keys in either config file that the server does not read.
        unknown: Vec<String>,
        /// Keys the shipped config holds more than once, active or commented.
        duplicates: Vec<String>,
    }

    fn config_gate(known: &BTreeSet<String>, shipped: &str, dev: &str) -> GateFindings {
        let shipped_keys = config_file_keys(shipped);
        let mut seen = BTreeSet::new();
        let duplicates: BTreeSet<String> = shipped_keys.iter().filter(|key| !seen.insert(*key)).cloned().collect();
        let mut all_keys = config_file_keys(dev);
        all_keys.extend(shipped_keys.iter().cloned());
        GateFindings {
            missing: known.iter().filter(|key| !shipped_keys.contains(key)).cloned().collect(),
            unknown: unknown_keys(all_keys, known),
            duplicates: duplicates.into_iter().collect(),
        }
    }

    /// Keys a config file sets, active or commented, once per occurrence.
    fn config_file_keys(content: &str) -> Vec<String> {
        let table = content.parse().unwrap_or_else(|e| panic!("config file does not parse: {e}"));
        let mut keys = commented_keys(content);
        toml_keys(&table, "", &mut keys);
        keys
    }

    /// Keys written as `# name = value` with a `[a-z][a-z0-9_]*` name, under
    /// the latest section header, active or commented (`# [x]`, `# [[x]]`).
    fn commented_keys(content: &str) -> Vec<String> {
        let mut section = "";
        let mut keys = Vec::new();
        for line in content.lines() {
            if let Some(header) = line.trim_start().strip_prefix('[').or_else(|| line.strip_prefix("# [")) {
                section = header.trim_start_matches('[').split(']').next().unwrap_or_default().trim();
            } else if let Some((name, _)) = line.strip_prefix("# ").and_then(|rest| rest.split_once(" = ")) {
                let is_key = name.starts_with(|c: char| c.is_ascii_lowercase())
                    && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                if is_key {
                    keys.push(if section.is_empty() { name.to_string() } else { format!("{section}.{name}") });
                }
            }
        }
        keys
    }

    // Test 2: commented keys count as present, explanation lines count as
    // nothing, and each finding names its keys.
    #[test]
    fn test_config_gate_on_synthetic_configs() {
        let known: BTreeSet<String> =
            ["server.port", "server.swagger_url", "backup.schedule.name"].map(String::from).into();
        let complete = "[server]\n# 0 = off\nport = 1\n# swagger_url = \"/x\"\n\n# [[backup.schedule]]\n# name = \"n\"\n";
        assert_eq!(config_gate(&known, complete, ""), GateFindings::default());

        let without_swagger_url = "[server]\nport = 1\n# [[backup.schedule]]\n# name = \"n\"\n";
        assert_eq!(
            config_gate(&known, without_swagger_url, ""),
            GateFindings { missing: vec!["server.swagger_url".into()], ..Default::default() }
        );

        let with_unknown = format!("{complete}[metrics]\nwindow_secs = 60\n");
        assert_eq!(
            config_gate(&known, &with_unknown, "[server]\n# hello = 1\n"),
            GateFindings { unknown: vec!["metrics.window_secs".into(), "server.hello".into()], ..Default::default() }
        );

        let port_twice = format!("{complete}# [server]\n# port = 2\n");
        assert_eq!(
            config_gate(&known, &port_twice, ""),
            GateFindings { duplicates: vec!["server.port".into()], ..Default::default() }
        );
    }

    const SHIPPED_CONFIG: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/luradb.toml"));
    const DEV_CONFIG: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/luradb.toml"));

    // Test 1: the gate on the real files.
    #[test]
    fn test_config_gate_on_shipped_and_dev_config() {
        let findings = config_gate(&known_keys(), SHIPPED_CONFIG, DEV_CONFIG);
        assert!(
            findings == GateFindings::default(),
            "packaging/luradb.toml, luradb.toml and the config types diverge.\n\
             missing: add each key to packaging/luradb.toml with an explanation line above it\n\
             unknown: remove the key from the file, or read it in a config type\n\
             duplicates: keep one line per key in packaging/luradb.toml\n{findings:#?}"
        );
    }

    // The release smoke test starts the shipped config; both files must pass
    // the startup checks.
    #[test]
    fn test_shipped_and_dev_config_pass_startup_checks() {
        let tmp = tempfile::TempDir::new().unwrap();
        for content in [SHIPPED_CONFIG, DEV_CONFIG] {
            let (config, unknown) = LuraConfig::parse(content).unwrap();
            assert!(unknown.is_empty(), "{unknown:?}");
            config.server.validate().unwrap();
            config.log.validate().unwrap();
            config.backup.validate().unwrap();
            config.validate_data_paths(tmp.path()).unwrap();
            config.auth.validate(&config.server).unwrap();
            config.cors.validate().unwrap();
            config.lsm.validate().unwrap();
            config.json.validate().unwrap();
            config.rel.validate().unwrap();
            config.shm.validate().unwrap();
            config.shm.validate_registration_socket(&config.server).unwrap();
            config.multicore.validate(1).unwrap();
        }
    }
}
