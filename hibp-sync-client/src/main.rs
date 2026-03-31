use std::path::PathBuf;
use std::process;

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
        process::exit(1);
    }

    let config =
        Config { server_url: args.server_url, data_dir: args.data_dir, segments: args.segments };

    match sync(&config).await {
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
            process::exit(1);
        }
    }
}
