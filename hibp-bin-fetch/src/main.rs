use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::{Parser, Subcommand};
use hibp_bin_fetch::serve::{ServeArgs, run as serve_run};
use hibp_bin_fetch::{Error, TOTAL_PREFIXES, get_completed_prefixes, worker};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs;

fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|_| "must be a positive integer".to_string())?;
    if n == 0 {
        return Err("must be >= 1".to_string());
    }
    Ok(n)
}

#[derive(Parser, Debug)]
#[command(name = "hibp-bin-fetch")]
#[command(
    about = "Download Have I Been Pwned password hashes to compact 6-byte binary format for use with hibp-verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Download the full HIBP dataset to a local directory
    Fetch(FetchArgs),
    /// Run as a sync server, downloading nightly and serving changed files to clients
    Serve(ServeArgs),
}

#[derive(clap::Args, Debug)]
struct FetchArgs {
    /// Output directory for binary files
    #[arg(short, long)]
    output: PathBuf,

    /// Number of concurrent download workers
    #[arg(short = 'j', long, default_value = "64", value_parser = parse_positive_usize)]
    concurrent_workers: usize,

    /// Resume a previous download (skip existing files)
    #[arg(long)]
    resume: bool,

    /// Overwrite existing output directory
    #[arg(long)]
    force: bool,

    /// Maximum prefix index to download (default: all 1,048,575)
    #[arg(long, default_value_t = TOTAL_PREFIXES - 1)]
    limit: u32,

    /// Enable progress bar (default: true)
    #[arg(long, default_value_t = true)]
    progress: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match cli.command {
        Command::Fetch(args) => fetch(args).await,
        Command::Serve(args) => serve_run(args, None).await,
    }
}

async fn fetch(args: FetchArgs) -> Result<(), Error> {
    if args.concurrent_workers == 0 {
        return Err(Error::InvalidConfig("concurrent workers must be >= 1"));
    }

    if args.resume && args.force {
        return Err(Error::InvalidArgs);
    }

    if args.output.exists() {
        if !args.resume && !args.force {
            return Err(Error::FileExists { path: args.output.clone() });
        }
        if args.force && !args.resume {
            fs::remove_dir_all(&args.output).await?;
        }
    }

    fs::create_dir_all(&args.output).await?;

    let completed = if args.resume {
        get_completed_prefixes(&args.output).await?
    } else {
        HashSet::new()
    };

    let prefixes_to_download: Vec<u32> =
        (0..=args.limit).filter(|p| !completed.contains(p)).collect();

    let total_to_download = prefixes_to_download.len() as u64;

    if total_to_download == 0 {
        println!("Nothing to download - all prefixes already exist.");
        return Ok(());
    }

    println!(
        "Downloading {} prefixes to {:?} using {} concurrent workers",
        total_to_download, args.output, args.concurrent_workers
    );

    if args.resume && !completed.is_empty() {
        println!("Resuming: {} prefixes already completed", completed.len());
    }

    let progress_counter = Arc::new(AtomicU64::new(0));
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrent_workers)
        .build()
        .expect("Failed to create HTTP client");

    let chunk_size = prefixes_to_download.len().div_ceil(args.concurrent_workers);
    let chunks: Vec<Vec<u32>> =
        prefixes_to_download.chunks(chunk_size).map(|c| c.to_vec()).collect();

    let progress_bar = if args.progress {
        let pb = ProgressBar::new(total_to_download);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .expect("Invalid progress bar template")
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let progress_counter_clone = Arc::clone(&progress_counter);
    let progress_bar_clone = progress_bar.clone();
    let progress_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = progress_counter_clone.load(Ordering::Relaxed);
            if let Some(ref pb) = progress_bar_clone {
                pb.set_position(current);
            }
            if current >= total_to_download {
                break;
            }
        }
    });

    let mut handles = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let client = client.clone();
        let output_dir = args.output.clone();
        let progress = Arc::clone(&progress_counter);
        handles.push(tokio::spawn(async move {
            worker(client, output_dir, chunk, progress).await
        }));
    }

    let mut first_error: Option<Error> = None;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error =
                        Some(Error::Io(io::Error::other(format!("Task panicked: {}", e))));
                }
            }
        }
    }

    progress_task.abort();
    if let Some(pb) = progress_bar {
        pb.finish_with_message("done");
    }

    if let Some(e) = first_error {
        return Err(e);
    }

    println!("Download complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_rejects_zero_workers() {
        let args = FetchArgs {
            output: tempfile::tempdir().unwrap().path().join("out"),
            concurrent_workers: 0,
            resume: false,
            force: false,
            limit: TOTAL_PREFIXES - 1,
            progress: false,
        };

        let err = fetch(args).await.unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
