use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::Parser;
use hibp_downloader::{Error, TOTAL_PREFIXES, get_completed_prefixes, worker};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs;

#[derive(Parser, Debug)]
#[command(name = "hibp-downloader")]
#[command(about = "Download Have I Been Pwned password hashes to compact binary format")]
struct Args {
    /// Output directory for binary files
    #[arg(short, long)]
    output: PathBuf,

    /// Number of concurrent download workers
    #[arg(short = 'j', long, default_value = "64")]
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

    /// Disable progress bar
    #[arg(long)]
    no_progress: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    // Validate arguments
    if args.resume && args.force {
        return Err(Error::InvalidArgs);
    }

    // Handle output directory
    if args.output.exists() {
        if !args.resume && !args.force {
            return Err(Error::FileExists { path: args.output.clone() });
        }
        if args.force && !args.resume {
            fs::remove_dir_all(&args.output).await?;
        }
    }

    fs::create_dir_all(&args.output).await?;

    // Determine which prefixes need downloading
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

    // Create shared state
    let progress_counter = Arc::new(AtomicU64::new(0));
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrent_workers)
        .build()
        .expect("Failed to create HTTP client");

    // Divide prefixes among workers
    let chunk_size = prefixes_to_download.len().div_ceil(args.concurrent_workers);
    let chunks: Vec<Vec<u32>> =
        prefixes_to_download.chunks(chunk_size).map(|c| c.to_vec()).collect();

    // Set up progress bar
    let progress_bar = if !args.no_progress {
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

    // Spawn progress updater task
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

    // Spawn worker tasks
    let mut handles = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let client = client.clone();
        let output_dir = args.output.clone();
        let progress = Arc::clone(&progress_counter);
        handles.push(tokio::spawn(async move {
            worker(client, output_dir, chunk, progress).await
        }));
    }

    // Wait for all workers to complete
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
                    first_error = Some(Error::Io(std::io::Error::other(format!(
                        "Task panicked: {}",
                        e
                    ))));
                }
            }
        }
    }

    // Clean up progress
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
