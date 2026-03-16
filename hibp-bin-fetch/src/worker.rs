use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use compact_str::CompactString;
use tokio::fs;

use crate::conversion::{line_to_sha1t48, prefix_to_hex};
use crate::error::Error;

const MAX_RETRIES: u32 = 10;
const RETRY_BASE_DELAY_MS: u64 = 100;

static BASE_URL: &[u8; 37] = b"https://api.pwnedpasswords.com/range/";

fn hibp_url(prefix: &[u8]) -> [u8; 42] {
    let mut out = [0u8; 42];
    out[..37].copy_from_slice(BASE_URL);
    out[37..].copy_from_slice(prefix);
    out
}

/// Fetch a prefix from the HIBP API and return the converted binary bytes.
/// `prefix_str` must be the 5-character uppercase hex representation of `prefix`.
#[tracing::instrument(skip(client, records_buf), fields(prefix = prefix_str))]
pub async fn fetch_prefix_bytes(
    client: &reqwest::Client,
    prefix: u32,
    prefix_str: &str,
    records_buf: &mut Vec<[u8; 6]>,
) -> Result<Vec<u8>, Error> {
    let buf = hibp_url(prefix_str.as_bytes());
    // SAFETY: Garaunteed to be valid utf-8 and enforced by tests.
    let url = unsafe { std::str::from_utf8_unchecked(&buf) };

    let mut last_error = None;
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY_MS * (1 << attempt.min(10));
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match client.get(url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    last_error = Some(Error::HttpStatus {
                        prefix: CompactString::new(prefix_str),
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
                        let bytes: Vec<u8> =
                            records_buf.iter().flat_map(|r| r.iter().copied()).collect();
                        return Ok(bytes);
                    }
                    Err(e) => {
                        last_error = Some(Error::HttpRequest {
                            prefix: CompactString::new(prefix_str),
                            source: e,
                        });
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error =
                    Some(Error::HttpRequest { prefix: CompactString::new(prefix_str), source: e });
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::MaxRetriesExceeded {
        prefix: CompactString::new(prefix_str),
        retries: MAX_RETRIES,
    }))
}

/// Download a single prefix and write it to a binary file in the output directory.
#[tracing::instrument(skip(client, output_dir, records_buf))]
pub async fn download_and_write_prefix(
    client: &reqwest::Client,
    output_dir: &Path,
    prefix: u32,
    records_buf: &mut Vec<[u8; 6]>,
) -> Result<(), Error> {
    let prefix_hex = prefix_to_hex(prefix);
    let prefix_str = std::str::from_utf8(&prefix_hex).unwrap();
    let bytes = fetch_prefix_bytes(client, prefix, prefix_str, records_buf).await?;
    let file_path = bin_path(output_dir, prefix_str);
    fs::write(&file_path, &bytes).await?;
    Ok(())
}

pub(crate) fn bin_path(dir: &Path, prefix_str: &str) -> PathBuf {
    let mut buf = [0u8; 9];
    buf[..5].copy_from_slice(prefix_str.as_bytes());
    buf[5..].copy_from_slice(b".bin");

    // SAFETY: Garaunteed to be valid utf8 bytes.
    let filename = unsafe { std::str::from_utf8_unchecked(&buf) };
    dir.join(filename)
}

/// Fetch a prefix, compare its SHA-256 digest against the stored digest, and write to
/// staging only if the content has changed. Returns true if the file was written to staging.
///
/// Digest files are intentionally not updated here. They are updated only after a successful
/// commit from staging -> data so interrupted downloads cannot advance digest state.
#[tracing::instrument(skip(client, digests_dir, staging_dir, records_buf))]
pub async fn download_and_write_prefix_digest(
    client: &reqwest::Client,
    digests_dir: &Path,
    staging_dir: &Path,
    prefix: u32,
    records_buf: &mut Vec<[u8; 6]>,
) -> Result<bool, Error> {
    let prefix_hex = prefix_to_hex(prefix);
    let prefix_str = std::str::from_utf8(&prefix_hex).unwrap();
    let bytes = fetch_prefix_bytes(client, prefix, prefix_str, records_buf).await?;
    let new_digest = crate::digest::compute(&bytes);

    let existing = crate::digest::read(digests_dir, prefix).await?;
    if existing.as_ref() == Some(&new_digest) {
        return Ok(false);
    }

    let staging_path = bin_path(staging_dir, prefix_str);
    fs::write(&staging_path, &bytes).await?;

    Ok(true)
}

/// Worker task for fetch mode: processes a range of prefixes, writing directly to output_dir.
#[tracing::instrument(skip_all)]
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

/// Worker task for serve mode: processes a range of prefixes, writing changed files to staging.
#[tracing::instrument(skip_all)]
pub async fn serve_worker(
    client: reqwest::Client,
    digests_dir: PathBuf,
    staging_dir: PathBuf,
    prefixes: Vec<u32>,
    progress: Arc<AtomicU64>,
) -> Result<(), Error> {
    let mut records_buf: Vec<[u8; 6]> = Vec::with_capacity(2000);
    for prefix in prefixes {
        download_and_write_prefix_digest(
            &client,
            &digests_dir,
            &staging_dir,
            prefix,
            &mut records_buf,
        )
        .await?;
        progress.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Scan output directory for existing .bin files and return completed prefix indices.
#[tracing::instrument]
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

#[cfg(test)]
mod tests {
    use crate::worker::hibp_url;

    /// Verify that binary bytes written to disk are read back verbatim with no transformation.
    /// This includes byte values that could be misinterpreted as line endings (0x0A, 0x0D)
    /// or other control characters, confirming that digest comparison is sound.
    #[tokio::test]
    async fn write_read_roundtrip_preserves_all_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");

        let bytes: Vec<u8> = (0u8..=255u8).cycle().take(768).collect();
        tokio::fs::write(&path, &bytes).await.unwrap();
        let read_back = tokio::fs::read(&path).await.unwrap();

        assert_eq!(bytes, read_back, "binary file round-trip must be lossless");

        let digest_written = crate::digest::compute(&bytes);
        let digest_read = crate::digest::compute(&read_back);
        assert_eq!(
            digest_written, digest_read,
            "digest of written bytes must match digest of read-back bytes"
        );
    }

    /// Verify that digest round-trip through disk (write/read) is lossless.
    #[tokio::test]
    async fn digest_write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let prefix: u32 = 0xABCDE;
        let bytes: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let digest = crate::digest::compute(&bytes);

        crate::digest::write(dir.path(), prefix, &digest).await.unwrap();
        let read_back = crate::digest::read(dir.path(), prefix).await.unwrap();

        assert_eq!(
            Some(digest),
            read_back,
            "stored digest must be read back identically"
        );
    }

    /// Verify that stack based writing of url is correct and equivalent.
    #[test]
    fn stack_url_matches() {
        let prefix_str = "ABCDE";
        let expect = format!("https://api.pwnedpasswords.com/range/{}", prefix_str);

        let buf = hibp_url(prefix_str.as_bytes());
        let got = unsafe { std::str::from_utf8_unchecked(&buf) };
        assert_eq!(expect, got);
    }
}
