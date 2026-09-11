use crate::core::wal::WAL_MAX_FIELD_LEN;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
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
    pub block_cache: BlockCacheConfig,
    pub lsm: LsmConfig,
    pub compaction: CompactionCfg,
    pub janitor: JanitorCfg,
    pub ttl_sweeper: TtlSweeperCfg,
    pub domains: DomainsConfig,
    pub rate_limit: RateLimitConfig,
    pub log: LogConfig,
    pub auth: AuthConfig,
    pub metrics: MetricsCfg,
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
            block_cache: BlockCacheConfig::default(),
            lsm: LsmConfig::default(),
            compaction: CompactionCfg::default(),
            janitor: JanitorCfg::default(),
            ttl_sweeper: TtlSweeperCfg::default(),
            domains: DomainsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            log: LogConfig::default(),
            auth: AuthConfig::default(),
            metrics: MetricsCfg::default(),
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
    /// Loads config from `path`. Returns `Default` if the file does not exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
        Ok(config)
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
    /// Filesystem mode for the socket (e.g. 432 = 0o660). Default: 0o660.
    pub unix_socket_mode: Option<u32>,
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
            unix_socket_mode: None,
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
    /// Number of registered buffer slots (Default: 128).
    pub registered_buffer_count: usize,
    /// Size of each slot in bytes (Default: 65536 = 64 KB).
    pub registered_buffer_size: usize,
    /// Storage thread: use an io_uring SQPOLL ring (Default: true). Falls back
    /// to the standard ring on EPERM (missing CAP_SYS_NICE).
    pub sqpoll_enabled: bool,
    /// SQPOLL kernel-thread idle timeout in milliseconds (Default: 2000).
    pub sqpoll_idle_ms: u32,
    /// CPU core to pin the storage thread to (`-1` = no pinning). Default: -1.
    pub storage_thread_cpu: i32,
    /// io_uring submission/completion queue depth (Default: 256).
    pub ring_depth: u32,
    /// Bounded request channel capacity for backpressure (Default: 1024).
    pub request_channel_capacity: usize,
}

impl Default for IoEngineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            registered_buffer_count: 128,
            registered_buffer_size: 65536,
            sqpoll_enabled: true,
            sqpoll_idle_ms: 2000,
            storage_thread_cpu: -1,
            ring_depth: 256,
            request_channel_capacity: 1024,
        }
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
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
    /// Access SSTables via mmap (perf/003). `false` = load files fully (escape hatch).
    pub use_mmap: bool,
    /// KV watch replay-ring capacity (spec kv/024). `0` disables resume —
    /// every reconnect with a `Last-Event-ID` gets `reset`, but `id:` fields
    /// are still assigned. Only the KV engine uses this; json/rel force it
    /// to `0` (no watch endpoint there).
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
            use_mmap: true,
            watch_replay_buffer_size: 1024,
        }
    }
}

impl LsmConfig {
    /// Startup validation (spec general/025): `max_value_size` and
    /// `max_key_length` are the two WAL length-prefixed fields this engine
    /// writes. A value above `WAL_MAX_FIELD_LEN` would still write today and
    /// only fail recovery on the *next* restart -- reject it at startup
    /// instead. `prefix` names the TOML block (`"lsm"`, `"json.lsm"`,
    /// `"rel.lsm"`) in the error message.
    pub fn validate(&self, prefix: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_value_size <= WAL_MAX_FIELD_LEN,
            "invalid config: {prefix}.max_value_size ({}) exceeds the WAL recovery field cap ({WAL_MAX_FIELD_LEN} bytes) — writes this large could never be recovered",
            self.max_value_size
        );
        anyhow::ensure!(
            self.max_key_length <= WAL_MAX_FIELD_LEN,
            "invalid config: {prefix}.max_key_length ({}) exceeds the WAL recovery field cap ({WAL_MAX_FIELD_LEN} bytes) — writes this large could never be recovered",
            self.max_key_length
        );
        Ok(())
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

// ── Metrics ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsCfg {
    pub window_secs: u64,
    pub ticker_interval_ms: u64,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        Self {
            window_secs: 60,
            ticker_interval_ms: 1000,
        }
    }
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
    /// Empty = stdout only. Recommended for systemd: "/var/log/luradb".
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
    pub domains: Option<LogLevel>,
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

/// Config for the JSON engine's dedicated LSM instance (own paths & tuning).
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct JsonStoreConfig {
    /// Set to `false` to skip starting the JSON engine entirely.
    pub enabled: bool,
    pub wal_path: String,
    pub vlog_path: String,
    pub sstable_dir: String,
    pub max_document_key_length: usize,
    /// Documents per atomic write batch during bulk load.
    pub bulk_batch_size: usize,
    /// Max HTTP request-body size for `/json/{domain}/bulk` in bytes
    /// (default 64 MB). Raises axum's 2 MB default so NDJSON exports can be
    /// re-imported in one request.
    pub bulk_body_limit_bytes: usize,
    /// Documents per re-index batch.
    pub reindex_batch_size: usize,
    /// Throttle pause between re-index batches (ms).
    pub reindex_pause_ms: u64,
    /// Keys tombstoned per purger tick.
    pub purger_batch_size: usize,
    /// Seconds between purger ticks.
    pub purger_interval_secs: u64,
    pub lsm: LsmConfig,
    pub compaction: CompactionCfg,
    pub janitor: JanitorCfg,
    pub block_cache: BlockCacheConfig,
}

impl Default for JsonStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            wal_path: "luradb_json.wal".to_string(),
            vlog_path: "luradb_json.vlog".to_string(),
            sstable_dir: "luradb_json_sstables".to_string(),
            max_document_key_length: 256,
            bulk_batch_size: 100,
            bulk_body_limit_bytes: 64 * 1024 * 1024,
            reindex_batch_size: 500,
            reindex_pause_ms: 10,
            purger_batch_size: 100,
            purger_interval_secs: 5,
            lsm: LsmConfig::default(),
            compaction: CompactionCfg::default(),
            janitor: JanitorCfg::default(),
            block_cache: BlockCacheConfig::default(),
        }
    }
}

// ── Relational Store (spec rel/001) ───────────────────────────────────────────

/// Config for the relational engine's dedicated LSM instance (own paths &
/// tuning). No `db_path` — like the JSON engine, this LSM instance has no
/// buffer-pool/DiskManager stack, so there is no database file to point at.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RelStoreConfig {
    /// Set to `false` to skip starting the relational engine entirely.
    pub enabled: bool,
    pub wal_path: String,
    pub vlog_path: String,
    pub sstable_dir: String,
    /// Catalog limits (spec rel/003, concept 8).
    pub max_columns: usize,
    pub max_indexes_per_table: usize,
    pub max_tables_per_domain: usize,
    /// SQL frontend guard (spec rel/004, concept 8): a statement longer than
    /// this many bytes is rejected before lexing.
    pub max_statement_len: usize,
    /// DML write-path guards (spec rel/005, concept 8): max bytes per
    /// TEXT/KVREF/JSONREF value and max encoded LuraRow size.
    pub max_text_len: usize,
    pub max_row_size: usize,
    /// SELECT executor limits (spec rel/006, concept 8): applied when no
    /// explicit LIMIT is given, the hard cap on any explicit LIMIT, and the
    /// hard cap on the in-memory ORDER BY sort buffer.
    pub default_limit: usize,
    pub max_limit: usize,
    pub max_sort_rows: usize,
    /// JOIN governance (spec rel/007, concept 8): max `LEFT JOIN` stages per
    /// statement, and whether an unindexed join column may fall back to a
    /// per-row full scan (dev/tiny-table escape hatch) instead of a 400.
    pub max_join_depth: usize,
    pub allow_unindexed_joins: bool,
    /// REST response cap (spec rel/009, concept 8): the `/sql` handler
    /// rejects a serialized response (incl. `expanded`) larger than this
    /// with 413, after `max_limit`/`max_sort_rows`/`max_join_depth` already
    /// bounded its shape — the backstop, especially for expand fan-out.
    pub max_response_bytes: usize,
    /// Cross-engine sweep (spec rel/012 §5/§8): seconds between sweep ticks,
    /// and the max cells nulled per (domain, column, tick). A separate, gentler
    /// cadence than the rel/013 purger (read-modify-write on live rows).
    pub cross_engine_sweep_interval_secs: u64,
    pub cross_engine_sweep_batch_size: usize,
    /// Domain purger (spec rel/013 §6): data keys/candidate probes tombstoned
    /// per batch, and seconds between ticks. Mirrors `[json]`.
    pub purger_batch_size: usize,
    pub purger_interval_secs: u64,
    /// Body-size cap for `POST .../tables/from-file` (spec rel/019), analogous
    /// to `json.bulk_body_limit_bytes`.
    pub import_body_limit_bytes: usize,
    pub lsm: LsmConfig,
    pub compaction: CompactionCfg,
    pub janitor: JanitorCfg,
    pub block_cache: BlockCacheConfig,
}

impl Default for RelStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            wal_path: "luradb_rel.wal".to_string(),
            vlog_path: "luradb_rel.vlog".to_string(),
            sstable_dir: "luradb_rel_sstables".to_string(),
            max_columns: 128,
            max_indexes_per_table: 16,
            max_tables_per_domain: 256,
            max_statement_len: 64 * 1024,
            max_text_len: 64 * 1024,
            max_row_size: 512 * 1024,
            default_limit: 1_000,
            max_limit: 10_000,
            max_sort_rows: 100_000,
            max_join_depth: 8,
            allow_unindexed_joins: false,
            max_response_bytes: 32 * 1024 * 1024,
            cross_engine_sweep_interval_secs: 10,
            cross_engine_sweep_batch_size: 100,
            purger_batch_size: 100,
            purger_interval_secs: 5,
            import_body_limit_bytes: 64 * 1024 * 1024,
            lsm: LsmConfig::default(),
            compaction: CompactionCfg::default(),
            janitor: JanitorCfg::default(),
            block_cache: BlockCacheConfig::default(),
        }
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
    /// Size of the state-header segment in bytes (Default: 4096).
    pub state_size: usize,
    /// Size of each double-buffer data segment in bytes (Default: 256 MB).
    pub data_buffer_size: usize,
    /// Size of the command ringbuffer segment in bytes; must be a power of
    /// two (Default: 4 MB). Also the size of every per-client cmd/resp ring.
    pub command_buffer_size: usize,
    /// Filesystem mode for created segments (Default: 0o660).
    pub segment_mode: u32,
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
            state_size: 4096,
            data_buffer_size: 268_435_456,
            command_buffer_size: 4_194_304,
            segment_mode: 0o660,
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

    /// Validates the size constraints the segment/ringbuffer code relies on.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.command_buffer_size.is_power_of_two(),
            "shm.command_buffer_size must be a power of two, got {}",
            self.command_buffer_size
        );
        // DoubleMmapRegion::new requires size >= page_size (4096); a smaller
        // power of two passes startup but fails every client registration.
        anyhow::ensure!(
            self.command_buffer_size >= 4096,
            "shm.command_buffer_size must be at least 4096 bytes, got {}",
            self.command_buffer_size
        );
        // Same bound the startup path checks, taken from the type itself so the
        // two can't drift apart (spec perf/012 §8).
        anyhow::ensure!(
            self.state_size >= crate::ipc::StateHeader::SIZE,
            "shm.state_size must be at least {} bytes, got {}",
            crate::ipc::StateHeader::SIZE,
            self.state_size
        );
        anyhow::ensure!(
            self.data_buffer_size >= 4096,
            "shm.data_buffer_size must be at least 4096 bytes, got {}",
            self.data_buffer_size
        );
        // '_' would make the stale-scan prefix `luradb_{id}_` ambiguous across
        // instances (id "0" would match and unlink live segments of "0_backup").
        anyhow::ensure!(
            !self.instance_id.is_empty()
                && self.instance_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "shm.instance_id must be non-empty and contain only [A-Za-z0-9-], got '{}'",
            self.instance_id
        );
        // 0 would turn the snapshot publisher into a busy loop of full scans.
        anyhow::ensure!(
            self.snapshot_interval_ms >= 1,
            "shm.snapshot_interval_ms must be at least 1, got {}",
            self.snapshot_interval_ms
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
    /// Entries scanned per batch and the pause between batches (pattern:
    /// json.reindex_batch_size/reindex_pause_ms) — keeps the foreground
    /// latency impact small. 0 is treated as 1.
    pub scan_batch_size: usize,
    pub scan_pause_ms: u64,
    /// Zero to many schedules; without one there are only on-demand backups.
    /// `[[backup.schedule]]` in TOML (singular) maps to this plural Vec field.
    pub schedule: Vec<BackupScheduleConfig>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: "luradb_backups".to_string(),
            scan_batch_size: 500,
            scan_pause_ms: 10,
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

impl BackupConfig {
    /// Startup validation (spec general/006, fail fast). A no-op when
    /// `enabled = false` — a disabled backup config runs no scheduler and
    /// serves no endpoints, so its contents are never acted on.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(!self.dir.is_empty(), "invalid config: backup.dir must not be empty");

        let mut seen_names = std::collections::HashSet::new();
        for sched in &self.schedule {
            anyhow::ensure!(
                crate::auth::handlers::valid_name(&sched.name),
                "invalid config: backup schedule name '{}' must be 1-50 characters of [a-zA-Z0-9_-]",
                sched.name
            );
            anyhow::ensure!(
                seen_names.insert(sched.name.clone()),
                "invalid config: duplicate backup schedule name '{}'",
                sched.name
            );
            crate::backup::cron::CronSchedule::parse(&sched.cron).map_err(|e| {
                anyhow::anyhow!(
                    "invalid config: backup schedule '{}' has an invalid cron expression '{}': {e}",
                    sched.name,
                    sched.cron
                )
            })?;
            crate::backup::BackupScope::parse(&sched.scope).map_err(|e| {
                anyhow::anyhow!(
                    "invalid config: backup schedule '{}' has an invalid scope '{}': {e}",
                    sched.name,
                    sched.scope
                )
            })?;
            anyhow::ensure!(
                sched.keep_last >= 1,
                "invalid config: backup schedule '{}' keep_last must be >= 1, got {}",
                sched.name,
                sched.keep_last
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

#[cfg(test)]
mod tests {
    use super::*;

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
            memtable_size_threshold = 8388608
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.json.enabled);
        assert_eq!(config.json.wal_path, "/data/json/wal.log");
        assert_eq!(config.json.lsm.memtable_size_threshold, 8 * 1024 * 1024);
        assert_eq!(config.json.vlog_path, "luradb_json.vlog");
        assert_eq!(config.json.compaction.l0_threshold, 4);
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
            memtable_size_threshold = 8388608
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.rel.enabled);
        assert_eq!(config.rel.wal_path, "/data/rel/wal.log");
        assert_eq!(config.rel.lsm.memtable_size_threshold, 8 * 1024 * 1024);
        assert_eq!(config.rel.vlog_path, "luradb_rel.vlog");
        assert_eq!(config.rel.compaction.l0_threshold, 4);
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
            unix_socket_mode = 432

            [auth]
            trusted_uids = [0, 1000]
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.unix_socket_path.as_deref(), Some("/run/luradb/luradb.sock"));
        assert_eq!(config.server.unix_socket_mode, Some(432));
        assert_eq!(config.auth.trusted_uids, vec![0, 1000]);
    }

    #[test]
    fn test_uds_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(config.server.unix_socket_path.is_none());
        assert!(config.server.unix_socket_mode.is_none());
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
        assert_eq!(config.io_engine.registered_buffer_count, 128);
        assert_eq!(config.io_engine.registered_buffer_size, 65536);
        // perf/005 storage-thread defaults
        assert!(config.io_engine.sqpoll_enabled);
        assert_eq!(config.io_engine.sqpoll_idle_ms, 2000);
        assert_eq!(config.io_engine.storage_thread_cpu, -1);
        assert_eq!(config.io_engine.ring_depth, 256);
        assert_eq!(config.io_engine.request_channel_capacity, 1024);
    }

    #[test]
    fn test_io_engine_toml_overrides() {
        let toml_str = r#"
            [io_engine]
            enabled = true
            registered_buffer_count = 64
            registered_buffer_size = 4096
            sqpoll_enabled = false
            sqpoll_idle_ms = 500
            storage_thread_cpu = 2
            ring_depth = 128
            request_channel_capacity = 256
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.io_engine.enabled);
        assert_eq!(config.io_engine.registered_buffer_count, 64);
        assert_eq!(config.io_engine.registered_buffer_size, 4096);
        assert!(!config.io_engine.sqpoll_enabled);
        assert_eq!(config.io_engine.sqpoll_idle_ms, 500);
        assert_eq!(config.io_engine.storage_thread_cpu, 2);
        assert_eq!(config.io_engine.ring_depth, 128);
        assert_eq!(config.io_engine.request_channel_capacity, 256);
    }

    #[test]
    fn test_shm_disabled_by_default() {
        let config = LuraConfig::default();
        assert!(!config.shm.enabled);
        assert_eq!(config.shm.instance_id, "0");
        assert_eq!(config.shm.state_size, 4096);
        assert_eq!(config.shm.data_buffer_size, 268_435_456);
        assert_eq!(config.shm.command_buffer_size, 4_194_304);
        assert_eq!(config.shm.segment_mode, 0o660);
    }

    #[test]
    fn test_shm_toml_overrides() {
        let toml_str = r#"
            [shm]
            enabled = true
            instance_id = "test"
            state_size = 8192
            command_buffer_size = 1048576
        "#;
        let config: LuraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.shm.enabled);
        assert_eq!(config.shm.instance_id, "test");
        assert_eq!(config.shm.state_size, 8192);
        assert_eq!(config.shm.command_buffer_size, 1_048_576);
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
    fn test_shm_command_buffer_size_must_be_power_of_two() {
        let mut config = ShmConfig::default();
        config.command_buffer_size = 3_000_000;
        assert!(config.validate().is_err());

        config.command_buffer_size = 4_194_304; // 2^22
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_shm_command_buffer_size_minimum() {
        let mut config = ShmConfig::default();
        // A power of two below the 4096-byte page size passes is_power_of_two
        // but is too small for DoubleMmapRegion — must be rejected at startup.
        config.command_buffer_size = 2048;
        assert!(config.validate().is_err());

        config.command_buffer_size = 4096;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_shm_state_and_data_size_minimums() {
        let mut config = ShmConfig::default();
        // The bound is the header size itself (spec perf/012 §8).
        config.state_size = crate::ipc::StateHeader::SIZE - 1;
        assert!(config.validate().is_err());
        config.state_size = crate::ipc::StateHeader::SIZE;
        assert!(config.validate().is_ok());

        config.state_size = 4096;
        config.data_buffer_size = 100;
        assert!(config.validate().is_err());

        config.data_buffer_size = 8192;
        config.snapshot_interval_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_shm_instance_id_charset() {
        let mut config = ShmConfig::default();
        config.instance_id = "0_backup".to_string();
        assert!(config.validate().is_err());

        config.instance_id = String::new();
        assert!(config.validate().is_err());

        config.instance_id = "prod-2".to_string();
        assert!(config.validate().is_ok());
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
        assert_eq!(config.backup.scan_batch_size, 500);
        assert_eq!(config.backup.scan_pause_ms, 10);
        assert!(config.backup.schedule.is_empty());
    }

    #[test]
    fn test_backup_toml_example_from_spec_parses() {
        let toml_str = r#"
            [backup]
            enabled = false
            dir = "luradb_backups"
            scan_batch_size = 500
            scan_pause_ms = 10

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
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_backup_validate_rejects_invalid_scope() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.scope = "not-a-scope".to_string();
        config.backup.schedule.push(sched);
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_backup_validate_rejects_keep_last_zero() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.keep_last = 0;
        config.backup.schedule.push(sched);
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_backup_validate_rejects_duplicate_schedule_names() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        config.backup.schedule.push(valid_backup_schedule("dup"));
        config.backup.schedule.push(valid_backup_schedule("dup"));
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_backup_validate_rejects_invalid_schedule_name_characters() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.name = "bad name!".to_string();
        config.backup.schedule.push(sched);
        assert!(config.backup.validate().is_err());
    }

    #[test]
    fn test_backup_validate_rejects_schedule_name_too_long() {
        let mut config = LuraConfig::default();
        config.backup.enabled = true;
        let mut sched = valid_backup_schedule("s1");
        sched.name = "a".repeat(51);
        config.backup.schedule.push(sched);
        assert!(config.backup.validate().is_err());
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
        assert!(config.lsm.validate("lsm").is_ok());
        assert!(config.json.lsm.validate("json.lsm").is_ok());
        assert!(config.rel.lsm.validate("rel.lsm").is_ok());
    }

    #[test]
    fn test_lsm_validate_max_value_size_at_cap_ok() {
        let mut lsm = LsmConfig::default();
        lsm.max_value_size = WAL_MAX_FIELD_LEN;
        assert!(lsm.validate("lsm").is_ok());
    }

    #[test]
    fn test_lsm_validate_max_value_size_over_cap_rejected() {
        let mut lsm = LsmConfig::default();
        lsm.max_value_size = WAL_MAX_FIELD_LEN + 1;
        let err = lsm.validate("lsm").unwrap_err().to_string();
        assert!(err.contains("lsm.max_value_size"), "{err}");
        assert!(err.contains(&(WAL_MAX_FIELD_LEN + 1).to_string()), "{err}");
        assert!(err.contains(&WAL_MAX_FIELD_LEN.to_string()), "{err}");
    }

    #[test]
    fn test_lsm_validate_max_key_length_over_cap_rejected() {
        let mut lsm = LsmConfig::default();
        lsm.max_key_length = WAL_MAX_FIELD_LEN + 1;
        let err = lsm.validate("lsm").unwrap_err().to_string();
        assert!(err.contains("lsm.max_key_length"), "{err}");
    }

    #[test]
    fn test_lsm_validate_json_lsm_over_cap_rejected() {
        let mut config = LuraConfig::default();
        config.json.lsm.max_value_size = WAL_MAX_FIELD_LEN + 1;
        let err = config.json.lsm.validate("json.lsm").unwrap_err().to_string();
        assert!(err.contains("json.lsm.max_value_size"), "{err}");
    }

    #[test]
    fn test_lsm_validate_rel_lsm_over_cap_rejected() {
        let mut config = LuraConfig::default();
        config.rel.lsm.max_value_size = WAL_MAX_FIELD_LEN + 1;
        let err = config.rel.lsm.validate("rel.lsm").unwrap_err().to_string();
        assert!(err.contains("rel.lsm.max_value_size"), "{err}");
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
}
