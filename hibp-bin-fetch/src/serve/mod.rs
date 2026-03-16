pub mod api;
pub mod download;
pub mod error;
pub mod state;

use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use api::AppState;
use chrono::{NaiveTime, TimeDelta, Utc};
use clap::Args;
use download::{Dirs, recover_if_needed, run_download_cycle};
use ntex::web;
use state::ServerState;
use tokio::sync::oneshot;

use crate::Error;

fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|_| "must be a positive integer".to_string())?;
    if n == 0 {
        return Err("must be >= 1".to_string());
    }
    Ok(n)
}

/// A UTC wall-clock time in HH:MM format used to schedule the nightly download.
#[derive(Debug, Clone)]
pub struct DownloadTime(pub NaiveTime);

impl FromStr for DownloadTime {
    type Err = chrono::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NaiveTime::parse_from_str(s, "%H:%M").map(DownloadTime)
    }
}

impl fmt::Display for DownloadTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format("%H:%M"))
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing::Level {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Directory to store data, digests, staging, and state files
    #[arg(long, default_value = "/var/lib/hibp-sync")]
    pub data_dir: PathBuf,

    /// Socket address to listen on
    #[arg(long, default_value = "0.0.0.0:8765")]
    pub listen: SocketAddr,

    /// Number of concurrent download workers
    #[arg(short = 'j', long, default_value = "64", value_parser = parse_positive_usize)]
    pub concurrent_workers: usize,

    /// UTC time for the nightly download cycle (HH:MM)
    #[arg(long, default_value = "03:00")]
    pub download_at: DownloadTime,

    /// Run a download cycle immediately on startup before serving
    #[arg(long)]
    pub download_on_start: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: LogLevel,
}

/// Start the serve daemon.
///
/// If `bound_tx` is provided, the actual bound `SocketAddr` is sent through it once the
/// server is listening. This is used by tests to discover the ephemeral port when
/// `args.listen` has port 0.
pub async fn run(
    args: ServeArgs,
    bound_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<(), Error> {
    if args.concurrent_workers == 0 {
        return Err(Error::InvalidConfig("concurrent workers must be >= 1"));
    }

    let level = tracing::Level::from(args.log_level);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.to_string())),
        )
        .try_init();

    // Pre-bind so the OS socket is in the listen state before we notify callers.
    let listener = TcpListener::bind(args.listen)?;
    let listen_addr = listener.local_addr()?;

    tracing::info!(
        data_dir = %args.data_dir.display(),
        listen = %listen_addr,
        workers = args.concurrent_workers,
        download_at = %args.download_at,
        "starting hibp-bin-fetch serve"
    );

    let dirs = Arc::new(Dirs::new(args.data_dir.clone()));
    dirs.ensure_all().await?;
    tracing::debug!("data directories verified");

    let server_state = {
        let loaded = ServerState::load(&args.data_dir).await?;
        tracing::info!(
            last_updated = ?loaded.sync.last_updated,
            changed_prefixes = loaded.changed.prefixes.len(),
            "loaded server state"
        );
        Arc::new(RwLock::new(loaded))
    };

    recover_if_needed(&dirs, Arc::clone(&server_state)).await?;

    if args.download_on_start {
        tracing::info!("running initial download cycle before serving");
        let client = build_client(args.concurrent_workers);
        run_download_cycle(
            &dirs,
            &client,
            args.concurrent_workers,
            Arc::clone(&server_state),
        )
        .await?;
    }

    let app_state = AppState { server_state: Arc::clone(&server_state), dirs: Arc::clone(&dirs) };

    {
        let dirs = Arc::clone(&dirs);
        let server_state = Arc::clone(&server_state);
        let workers = args.concurrent_workers;
        let download_at = args.download_at.0;
        tokio::spawn(async move {
            let client = build_client(workers);
            loop {
                let delay = duration_until_next(download_at);
                tracing::info!(
                    next_run_in_secs = delay.as_secs(),
                    "download cycle scheduled"
                );
                tokio::time::sleep(delay).await;
                if let Err(e) =
                    run_download_cycle(&dirs, &client, workers, Arc::clone(&server_state)).await
                {
                    tracing::error!(error = %e, "scheduled download cycle failed");
                }
            }
        });
    }

    let server = web::HttpServer::new(async move || {
        web::App::new()
            .state(app_state.clone())
            .service(api::get_status)
            .service(api::get_changed)
            .service(api::get_segment)
            .service(api::healthz)
    })
    .listen(listener)?;

    tracing::info!(addr = %listen_addr, "HTTP server listening");
    if let Some(tx) = bound_tx {
        let _ = tx.send(listen_addr);
    }

    server.run().await?;

    Ok(())
}

fn build_client(workers: usize) -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(workers)
        .build()
        .expect("failed to build HTTP client")
}

pub(crate) fn duration_until_next(target: NaiveTime) -> Duration {
    let now = Utc::now();
    let today = now.date_naive().and_time(target).and_utc();
    let next = if today > now {
        today
    } else {
        (now.date_naive() + TimeDelta::days(1)).and_time(target).and_utc()
    };
    Duration::from_secs((next - now).num_seconds().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_future_time() {
        let now = Utc::now();
        let target = (now + TimeDelta::hours(2)).time();
        let delay = duration_until_next(target);
        let secs = delay.as_secs();
        assert!((7190..=7210).contains(&secs), "expected ~7200s, got {secs}");
    }

    #[test]
    fn duration_past_time() {
        let now = Utc::now();
        let target = (now - TimeDelta::hours(1)).time();
        let delay = duration_until_next(target);
        let secs = delay.as_secs();
        // Should be ~23 hours from now
        assert!(
            (82_790..=82_810).contains(&secs),
            "expected ~82800s, got {secs}"
        );
    }
}
