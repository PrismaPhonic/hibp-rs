use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::fs;

use crate::conversion::{line_to_sha1t48, prefix_to_hex};
use crate::error::Error;

/// Maximum retries per prefix download
const MAX_RETRIES: u32 = 10;

/// Base delay for exponential backoff (doubles each retry)
const RETRY_BASE_DELAY_MS: u64 = 100;

/// Download a single prefix and write it to a binary file
pub async fn download_and_write_prefix(
    client: &reqwest::Client,
    output_dir: &Path,
    prefix: u32,
    records_buf: &mut Vec<[u8; 6]>,
) -> Result<(), Error> {
    let prefix_hex = prefix_to_hex(prefix);
    let prefix_str = std::str::from_utf8(&prefix_hex).unwrap();
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix_str);

    let mut last_error = None;
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY_MS * (1 << attempt.min(10));
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match client.get(&url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    last_error = Some(Error::HttpStatus {
                        prefix: prefix_str.to_string(),
                        status: response.status().as_u16(),
                    });
                    continue;
                }

                match response.text().await {
                    Ok(body) => {
                        records_buf.clear();

                        let mut record = [0u8; 6];

                        for line in body.lines() {
                            if line.is_empty() {
                                continue;
                            }
                            let line_bytes = line.as_bytes();
                            if line_bytes.len() >= 35 {
                                line_to_sha1t48(prefix, line_bytes, &mut record);
                                records_buf.push(record);
                            }
                        }

                        let file_path = output_dir.join(format!("{}.bin", prefix_str));
                        let bytes: Vec<u8> =
                            records_buf.iter().flat_map(|r| r.iter().copied()).collect();

                        fs::write(&file_path, &bytes).await?;

                        return Ok(());
                    }
                    Err(e) => {
                        last_error =
                            Some(Error::HttpRequest { prefix: prefix_str.to_string(), source: e });
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error = Some(Error::HttpRequest { prefix: prefix_str.to_string(), source: e });
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::MaxRetriesExceeded {
        prefix: prefix_str.to_string(),
        retries: MAX_RETRIES,
    }))
}

/// Worker task that processes a range of prefixes
pub async fn worker(
    client: reqwest::Client,
    output_dir: PathBuf,
    prefixes: Vec<u32>,
    progress: Arc<AtomicU64>,
) -> Result<(), Error> {
    let mut records_buf: Vec<[u8; 6]> = Vec::with_capacity(2000);
    for prefix in prefixes {
        download_and_write_prefix(&client, &output_dir, prefix, &mut records_buf).await?;
        progress.fetch_add(1, Ordering::Relaxed);
    }

    Ok(())
}

/// Scan output directory for existing .bin files and return completed prefix indices
pub async fn get_completed_prefixes(output_dir: &PathBuf) -> Result<HashSet<u32>, Error> {
    let mut completed = HashSet::new();
    if !output_dir.exists() {
        return Ok(completed);
    }

    let mut entries = fs::read_dir(output_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let prefix = path
            .extension()
            .filter(|ext| *ext == "bin")
            .and_then(|_| path.file_stem())
            .and_then(|stem| stem.to_str())
            .filter(|s| s.len() == 5)
            .and_then(|s| u32::from_str_radix(s, 16).ok());

        if let Some(p) = prefix {
            completed.insert(p);
        }
    }

    Ok(completed)
}
