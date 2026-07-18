use crate::config::{LogConfig, LogFormat, LogLevel};
use anyhow::Result;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging(cfg: &LogConfig) -> Result<Option<WorkerGuard>> {
    let filter = build_env_filter(cfg);

    if cfg.path.is_empty() {
        match cfg.format {
            LogFormat::Json => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json())
                    .init();
            }
            LogFormat::Text => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer())
                    .init();
            }
        }
        return Ok(None);
    }

    let appender = match cfg.rotation.as_str() {
        "hourly" => RollingFileAppender::new(Rotation::HOURLY, &cfg.path, "luradb.log"),
        "daily" => RollingFileAppender::new(Rotation::DAILY, &cfg.path, "luradb.log"),
        _ => RollingFileAppender::new(Rotation::NEVER, &cfg.path, "luradb.log"),
    };
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    match cfg.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(non_blocking))
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(non_blocking))
                .init();
        }
    }

    Ok(Some(guard))
}

fn build_env_filter(cfg: &LogConfig) -> EnvFilter {
    EnvFilter::new(directive_string(cfg))
}

/// Returns the effective filter directive string.
/// RUST_LOG takes precedence over the config-based string.
pub(crate) fn directive_string(cfg: &LogConfig) -> String {
    std::env::var("RUST_LOG").unwrap_or_else(|_| build_filter_string(cfg))
}

/// Builds the filter directive string from config (ignores RUST_LOG).
pub(crate) fn build_filter_string(cfg: &LogConfig) -> String {
    let global = level_to_str(&cfg.level);
    let mut directives = format!("luradb={global}");
    let modules: [(&str, &Option<LogLevel>); 5] = [
        ("luradb::auth", &cfg.modules.auth),
        ("luradb::api", &cfg.modules.api),
        ("luradb::engines", &cfg.modules.engine),
        ("luradb::engines::lsm::domain", &cfg.modules.domains),
        ("luradb::storage", &cfg.modules.storage),
    ];
    for (target, level_opt) in &modules {
        if let Some(lvl) = level_opt {
            write!(directives, ",{target}={}", level_to_str(lvl)).ok();
        }
    }
    directives
}

pub(crate) fn level_to_str(level: &LogLevel) -> &'static str {
    match level {
        LogLevel::Verbose => "debug",
        LogLevel::Info => "info",
        LogLevel::Prod => "warn",
    }
}

// ── LogJanitor ────────────────────────────────────────────────────────────────

pub struct LogJanitor {
    log_path: PathBuf,
    retention_days: u64,
}

impl LogJanitor {
    pub fn new(log_path: impl Into<PathBuf>, retention_days: u64) -> Self {
        Self {
            log_path: log_path.into(),
            retention_days,
        }
    }

    pub async fn run(self, shutdown: Arc<AtomicBool>) {
        let check_interval = Duration::from_secs(60);
        let run_interval = Duration::from_secs(86_400);
        let mut elapsed = Duration::ZERO;

        loop {
            tokio::time::sleep(check_interval).await;
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            elapsed += check_interval;
            if elapsed >= run_interval {
                elapsed = Duration::ZERO;
                self.cleanup().await;
            }
        }
    }

    async fn cleanup(&self) {
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(self.retention_days * 86_400))
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let mut entries = match tokio::fs::read_dir(&self.log_path).await {
            Ok(e) => e,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if !name.starts_with("luradb.log") {
                continue;
            }
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if mtime < cutoff {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogConfig, LogLevel, LogModulesConfig};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_level_mapping() {
        assert_eq!(level_to_str(&LogLevel::Verbose), "debug");
        assert_eq!(level_to_str(&LogLevel::Info), "info");
        assert_eq!(level_to_str(&LogLevel::Prod), "warn");
    }

    #[test]
    fn test_envfilter_build() {
        std::env::remove_var("RUST_LOG");
        let cfg = LogConfig {
            level: LogLevel::Info,
            modules: LogModulesConfig {
                auth: Some(LogLevel::Verbose),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = build_filter_string(&cfg);
        assert!(s.contains("luradb=info"), "Expected luradb=info in: {s}");
        assert!(s.contains("luradb::auth=debug"), "Expected luradb::auth=debug in: {s}");
    }

    #[test]
    fn test_rust_log_precedence() {
        std::env::remove_var("RUST_LOG");
        let cfg = LogConfig { level: LogLevel::Info, ..Default::default() };

        // Without RUST_LOG: directive_string returns config-based value
        assert!(directive_string(&cfg).starts_with("luradb=info"));

        // With RUST_LOG: directive_string returns the env var value
        std::env::set_var("RUST_LOG", "luradb=trace,tower_http=debug");
        assert_eq!(directive_string(&cfg), "luradb=trace,tower_http=debug");

        std::env::remove_var("RUST_LOG");
    }

    fn set_mtime_days_ago(path: &std::path::Path, days: u64) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let past = SystemTime::now()
            .checked_sub(Duration::from_secs(days * 86_400))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let secs = past
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let times = [
            libc::timeval { tv_sec: secs as libc::time_t, tv_usec: 0 },
            libc::timeval { tv_sec: secs as libc::time_t, tv_usec: 0 },
        ];
        unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
    }

    #[tokio::test]
    async fn test_janitor_cleanup_old_files() {
        let dir = tempdir().unwrap();

        let old = dir.path().join("luradb.log.2025-01-01");
        fs::write(&old, b"old log").unwrap();
        set_mtime_days_ago(&old, 35);

        let recent = dir.path().join("luradb.log.2026-02-19");
        fs::write(&recent, b"recent log").unwrap();
        // mtime stays at "now" — within retention window

        let janitor = LogJanitor::new(dir.path(), 30);
        janitor.cleanup().await;

        assert!(!old.exists(), "Old file should have been deleted");
        assert!(recent.exists(), "Recent file should survive");
    }

    #[tokio::test]
    async fn test_janitor_guard_luradb_only() {
        let dir = tempdir().unwrap();

        let lura_log = dir.path().join("luradb.log.old");
        fs::write(&lura_log, b"log").unwrap();
        set_mtime_days_ago(&lura_log, 40);

        let other = dir.path().join("important.txt");
        fs::write(&other, b"keep me").unwrap();
        set_mtime_days_ago(&other, 40);

        let janitor = LogJanitor::new(dir.path(), 30);
        janitor.cleanup().await;

        assert!(!lura_log.exists(), "luradb.log.old should be deleted");
        assert!(other.exists(), "important.txt must not be touched");
    }
}
