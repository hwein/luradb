use clap::Parser;
use luradb::{
    api::ApiDoc,
    config::{resolve_config_path, LuraConfig},
    core::coop,
    logging,
    server::Server,
};
use std::sync::Arc;
use tokio::signal;
use utoipa::OpenApi;

#[derive(Parser)]
#[command(about = "LuraDB – Linux-first, REST-native multi-model database")]
struct Cli {
    /// Path to the TOML configuration file. Default: ./luradb.toml if present,
    /// else /etc/luradb/luradb.toml if present, else ./luradb.toml (defaults).
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Prints the OpenAPI contract as JSON to stdout and exits.
    #[arg(long)]
    dump_openapi: bool,
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received. Starting graceful shutdown...");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.dump_openapi {
        println!("{}", ApiDoc::openapi().to_pretty_json().expect("OpenAPI spec must serialize"));
        return Ok(());
    }
    let config_path = resolve_config_path(cli.config, |p| p.exists());
    let (config, unknown_keys) = LuraConfig::load(&config_path)?;
    let config = Arc::new(config);
    config.server.validate()?;
    config.log.validate()?;
    config.backup.validate()?;
    let cwd = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("failed to determine the current working directory: {e}"))?;
    config.validate_data_paths(&cwd)?;
    config.auth.validate(&config.server)?;
    config.cors.validate()?;
    config.lsm.validate()?;
    config.json.validate()?;
    config.rel.validate()?;
    config.shm.validate_registration_socket(&config.server)?;
    config.multicore.validate(coop::available_cores())?;
    let _log_guard = logging::init_logging(&config.log)?;

    tracing::info!("Starting LuraDB...");
    if config_path.exists() {
        tracing::info!("Config loaded from {}", config_path.display());
    } else {
        tracing::info!("No config file found at {}, using defaults", config_path.display());
    }
    for key in &unknown_keys {
        tracing::warn!("unknown config key '{key}' is ignored");
    }
    // `config.auth.validate` already rejected a non-loopback bind above,
    // so reaching here with auth disabled means the dev-mode loopback
    // case (spec general/013) — allowed, but not silent.
    if !config.auth.enabled {
        tracing::warn!(
            "auth.enabled is false — the server is unauthenticated. Allowed only because server.bind_address ({}) is loopback-only.",
            config.server.bind_address
        );
    }

    Server::start(config, &config_path)?.run_until(shutdown_signal())
}
