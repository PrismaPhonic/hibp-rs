use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::client::Client;
use crate::error::Error;
use crate::wire::decode_segment_stream;

pub struct Config {
    pub server_url: http::Uri,
    pub data_dir: PathBuf,
    pub segments: u8,
}

pub enum Outcome {
    UpToDate,
    DeltaSync { changed_count: usize },
    FullSync { file_count: usize },
}

#[derive(Serialize, Deserialize, Default)]
struct LocalState {
    last_updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Plan {
    server_last_updated: DateTime<Utc>,
    since: Option<String>,
    segments: u8,
}

#[tracing::instrument(skip_all)]
pub async fn sync(config: &Config) -> Result<Outcome, Error> {
    if config.segments == 0 {
        return Err(Error::InvalidConfig("segments must be >= 1"));
    }

    let staging = config.data_dir.join(".staging");
    let complete_marker = staging.join(".complete");
    let plan_path = staging.join(".sync-plan.json");

    if staging.exists() {
        if complete_marker.exists() {
            tracing::info!("staging/.complete exists - finishing interrupted commit");
            return finish_commit(&staging, &config.data_dir).await;
        } else if plan_path.exists() {
            tracing::info!("resuming interrupted download");
            let plan: Plan = serde_json::from_slice(&fs::read(&plan_path).await?)?;

            let client = Client::new(&config.server_url)?;
            let status = client.status().await?;

            if status.last_updated != Some(plan.server_last_updated) {
                tracing::warn!(
                    "server state changed since last attempt; discarding staging and starting fresh"
                );
                clear_staging(&staging).await?;
            } else {
                fetch_missing_segments(&config.server_url, &staging, &plan).await?;
                fs::write(&complete_marker, b"").await?;
                return finish_commit(&staging, &config.data_dir).await;
            }
        } else {
            tracing::warn!("staging exists without .sync-plan.json; discarding");
            clear_staging(&staging).await?;
        }
    }

    let state_path = config.data_dir.join("sync-state.json");
    let local: LocalState = match fs::read(&state_path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => LocalState::default(),
        Err(e) => return Err(e.into()),
    };
    let client = Client::new(&config.server_url)?;
    let server_last_updated = match client.status().await?.last_updated {
        Some(t) => t,
        None => return Ok(Outcome::UpToDate),
    };

    if Some(server_last_updated) <= local.last_updated {
        return Ok(Outcome::UpToDate);
    }

    // Use Z-suffix format (e.g. "2026-01-01T00:00:00Z") so the value is URL-safe
    // without encoding when used as a query parameter.
    let since_opt: Option<String> = if local.last_updated.is_none() {
        None
    } else {
        let changed = client.changed().await?;
        if changed.prev_last_updated == local.last_updated {
            local.last_updated.map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
        } else {
            tracing::warn!(
                "server prev_last_updated does not match local last_updated; falling back to full sync"
            );
            None
        }
    };

    fs::create_dir_all(&staging).await?;

    let plan = Plan { server_last_updated, since: since_opt, segments: config.segments };
    fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?).await?;

    fetch_missing_segments(&config.server_url, &staging, &plan).await?;
    fs::write(&complete_marker, b"").await?;

    finish_commit(&staging, &config.data_dir).await
}

#[tracing::instrument(skip(server_url, staging), fields(segments = plan.segments, since = plan.since.as_deref()))]
async fn fetch_missing_segments(
    server_url: &http::Uri,
    staging: &Path,
    plan: &Plan,
) -> Result<(), Error> {
    let segments = plan.segments;
    let client = Client::new(server_url)?;

    for seg in 0..segments {
        if staging.join(format!(".seg.{}.done", seg)).exists() {
            continue;
        }
        fetch_segment_with_retry(&client, seg, segments, plan.since.as_deref(), staging).await?;
    }

    Ok(())
}

#[tracing::instrument(skip(client, staging))]
async fn fetch_segment_with_retry(
    client: &Client,
    segment: u8,
    of: u8,
    since: Option<&str>,
    staging: &Path,
) -> Result<(), Error> {
    const MAX_RETRIES: u32 = 5;
    let mut delay = Duration::from_millis(500);
    let mut last_result = Ok(());

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
        match client.segment_stream(segment, of, since).await {
            Ok(decoder) => {
                let mut stream = Box::pin(decode_segment_stream(decoder));
                while let Some(entry_res) = stream.next().await {
                    let entry = entry_res?;
                    let prefix_str = std::str::from_utf8(&entry.prefix)
                        .map_err(|e| Error::Decode(format!("invalid prefix bytes: {e}")))?;
                    fs::write(staging.join(format!("{}.bin", prefix_str)), &entry.content).await?;
                }
                fs::write(staging.join(format!(".seg.{}.done", segment)), b"").await?;
                return Ok(());
            }
            Err(e) => last_result = Err(e),
        }
    }

    last_result
}

#[tracing::instrument(skip_all)]
async fn finish_commit(staging: &Path, data_dir: &Path) -> Result<Outcome, Error> {
    let plan: Plan = serde_json::from_slice(&fs::read(staging.join(".sync-plan.json")).await?)?;

    let mut entries = fs::read_dir(staging).await?;
    let mut file_count = 0usize;
    while let Some(entry) = entries.next_entry().await? {
        let src = entry.path();
        if src.extension().is_some_and(|e| e == "bin") {
            fs::rename(&src, data_dir.join(src.file_name().unwrap())).await?;
            file_count += 1;
        }
    }

    let state_path = data_dir.join("sync-state.json");
    let new_state = LocalState { last_updated: Some(plan.server_last_updated) };
    let tmp = state_path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&new_state)?).await?;
    fs::rename(&tmp, &state_path).await?;

    clear_staging(staging).await?;

    Ok(match plan.since {
        Some(_) => Outcome::DeltaSync { changed_count: file_count },
        None => Outcome::FullSync { file_count },
    })
}

async fn clear_staging(staging: &Path) -> Result<(), Error> {
    fs::remove_dir_all(staging).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sync_rejects_zero_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            server_url: "http://127.0.0.1:8765".parse().unwrap(),
            data_dir: tmp.path().to_path_buf(),
            segments: 0,
        };

        match sync(&cfg).await {
            Err(Error::InvalidConfig(_)) => {}
            Err(e) => panic!("expected InvalidConfig, got {e}"),
            Ok(_) => panic!("expected error for zero segments"),
        }
    }
}
