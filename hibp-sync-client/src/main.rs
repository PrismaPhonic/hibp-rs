use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use chrono::{NaiveTime, TimeDelta, Utc};
use clap::Parser;
use hibp_sync_client::sync::{Config, Outcome, sync};
use http::Uri;

fn parse_segments(s: &str) -> Result<u8, String> {
    let n: u8 = s.parse().map_err(|_| "must be an integer in 1..=255".to_string())?;
    if n == 0 {
        return Err("must be in 1..=255".to_string());
    }
    Ok(n)
}

#[derive(Debug, Clone)]
struct SyncTime(NaiveTime);

impl FromStr for SyncTime {
    type Err = chrono::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NaiveTime::parse_from_str(s, "%H:%M").map(SyncTime)
    }
}

impl fmt::Display for SyncTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format("%H:%M"))
    }
}

fn duration_until_next(target: NaiveTime) -> Duration {
    let now = Utc::now();
    let today = now.date_naive().and_time(target).and_utc();
    let next = if today > now {
        today
    } else {
        (now.date_naive() + TimeDelta::days(1)).and_time(target).and_utc()
    };
    Duration::from_secs((next - now).num_seconds().max(0) as u64)
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum LogLevel {
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

#[derive(Parser, Debug)]
#[command(name = "hibp-sync-client")]
#[command(about = "Sync a local HIBP binary dataset from an hibp-bin-fetch serve instance")]
struct Args {
    /// URL of the hibp-bin-fetch serve instance
    #[arg(long)]
    server_url: Uri,

    /// Directory where .bin files are stored
    #[arg(long)]
    data_dir: PathBuf,

    /// Number of segments to split the sync into (controls resume granularity, max 255)
    #[arg(long, default_value = "16", value_parser = parse_segments)]
    segments: u8,

    /// UTC time to run the nightly sync cycle (HH:MM)
    #[arg(long, default_value = "04:00")]
    sync_at: SyncTime,

    /// Run a sync cycle immediately on startup before entering the nightly schedule
    #[arg(long)]
    sync_on_start: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: LogLevel,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::from(args.log_level))
        .init();

    if let Err(e) = tokio::fs::create_dir_all(&args.data_dir).await {
        tracing::error!(error = %e, "failed to create data directory");
        std::process::exit(1);
    }

    let config =
        Config { server_url: args.server_url, data_dir: args.data_dir, segments: args.segments };

    tracing::info!(
        sync_at = %args.sync_at,
        sync_on_start = args.sync_on_start,
        "starting hibp-sync-client"
    );

    if args.sync_on_start {
        run_sync(&config).await;
    }

    loop {
        let delay = duration_until_next(args.sync_at.0);
        tracing::info!(next_run_in_secs = delay.as_secs(), "sync cycle scheduled");
        tokio::time::sleep(delay).await;
        run_sync(&config).await;
    }
}

async fn run_sync(config: &Config) {
    match sync(config).await {
        Ok(Outcome::UpToDate) => {
            tracing::info!("already up to date");
        }
        Ok(Outcome::DeltaSync { changed_count }) => {
            tracing::info!(changed = changed_count, "delta sync complete");
        }
        Ok(Outcome::FullSync { file_count }) => {
            tracing::info!(files = file_count, "full sync complete");
        }
        Err(e) => {
            tracing::error!(error = %e, "sync failed");
        }
    }
}
