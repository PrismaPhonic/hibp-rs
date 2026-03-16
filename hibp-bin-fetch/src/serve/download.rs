use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use compact_str::CompactString;
use tokio::fs;

use super::state::{ChangedState, ServerState, SyncState, save_changed, save_sync};
use crate::conversion::prefix_to_hex;
use crate::worker::serve_worker;
use crate::{Error, TOTAL_PREFIXES};

pub struct Dirs {
    pub base: PathBuf,
    pub data: PathBuf,
    pub digests: PathBuf,
    pub staging: PathBuf,
}

impl Dirs {
    pub fn new(base: PathBuf) -> Self {
        let data = base.join("data");
        let digests = base.join("digests");
        let staging = base.join("staging");
        Self { base, data, digests, staging }
    }

    pub async fn ensure_all(&self) -> io::Result<()> {
        fs::create_dir_all(&self.data).await?;
        fs::create_dir_all(&self.digests).await?;
        fs::create_dir_all(&self.staging).await?;
        Ok(())
    }
}

/// Called at startup. Inspects staging/ and either finishes an interrupted commit or
/// discards a partial download, leaving staging/ empty and state consistent.
#[tracing::instrument(skip_all)]
pub async fn recover_if_needed(dirs: &Dirs, state: Arc<RwLock<ServerState>>) -> Result<(), Error> {
    let complete_marker = dirs.staging.join(".complete");
    let staging_nonempty = has_bin_files(&dirs.staging).await?;

    if !staging_nonempty {
        if complete_marker.exists() {
            tracing::warn!("stale .complete marker found with no staged .bin files; clearing");
            clear_staging(&dirs.staging).await?;
        }
        return Ok(());
    }

    if complete_marker.exists() {
        tracing::info!("staging/ has .complete marker - finishing interrupted commit");
        finish_commit(dirs, state).await
    } else {
        tracing::warn!(
            "staging/ is non-empty without .complete marker - download was interrupted; discarding"
        );
        clear_staging(&dirs.staging).await
    }
}

#[tracing::instrument(skip(dirs, client, state), fields(workers))]
pub async fn run_download_cycle(
    dirs: &Dirs,
    client: &reqwest::Client,
    workers: usize,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Error> {
    if workers == 0 {
        return Err(Error::InvalidConfig("concurrent workers must be >= 1"));
    }

    // Ensure each cycle starts from a clean staging area.
    clear_staging(&dirs.staging).await?;

    let progress = Arc::new(AtomicU64::new(0));
    let all_prefixes: Vec<u32> = (0..TOTAL_PREFIXES).collect();
    let chunk_size = all_prefixes.len().div_ceil(workers);
    let chunks: Vec<Vec<u32>> = all_prefixes.chunks(chunk_size).map(|c| c.to_vec()).collect();

    let mut handles = futures_util::stream::FuturesUnordered::new();
    for chunk in chunks {
        let client = client.clone();
        let digests_dir = dirs.digests.clone();
        let staging_dir = dirs.staging.clone();
        let progress = Arc::clone(&progress);
        handles.push(tokio::spawn(async move {
            serve_worker(client, digests_dir, staging_dir, chunk, progress).await
        }));
    }

    use futures_util::StreamExt;
    while let Some(res) = handles.next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(error = %e, "download cycle worker failed");
                return Err(e);
            }
            Err(e) => {
                let err = Error::Io(io::Error::other(format!("task panicked: {e}")));
                tracing::error!(error = %err, "download cycle worker panicked");
                return Err(err);
            }
        }
    }

    tracing::info!(
        processed = progress.load(Ordering::Relaxed),
        "all workers complete"
    );

    // Write .complete marker before doing anything else. This is the signal that all
    // prefixes were processed and it is safe to commit whatever is in staging/.
    fs::write(dirs.staging.join(".complete"), b"").await?;

    let changed_prefixes = enumerate_staging_bin_files(&dirs.staging).await?;
    if changed_prefixes.is_empty() {
        tracing::info!("download cycle complete: no changes");
        let complete = dirs.staging.join(".complete");
        match fs::remove_file(&complete).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let now = Utc::now();
        let new_sync = SyncState {
            last_updated: state.read().unwrap().sync.last_updated,
            last_checked: Some(now),
        };
        save_sync(&dirs.base, &new_sync).await?;
        state.write().unwrap().sync = new_sync;
        return Ok(());
    }

    tracing::info!(changed = changed_prefixes.len(), "committing changes");
    finish_commit(dirs, state).await
}

/// Copy staged files into data/, write state files atomically, then clear staging/.
/// Called both from run_download_cycle and from recover_if_needed.
#[tracing::instrument(skip_all)]
async fn finish_commit(dirs: &Dirs, state: Arc<RwLock<ServerState>>) -> Result<(), Error> {
    let changed_prefixes = enumerate_staging_bin_files(&dirs.staging).await?;
    if changed_prefixes.is_empty() {
        clear_staging(&dirs.staging).await?;
        return Ok(());
    }

    for &prefix in &changed_prefixes {
        let hex = prefix_to_hex(prefix);
        // SAFETY: prefix_to_hex produces only uppercase ASCII hex digits (0-9, A-F).
        let prefix_str = unsafe { std::str::from_utf8_unchecked(&hex) };
        let src = crate::worker::bin_path(&dirs.staging, prefix_str);
        let dst = crate::worker::bin_path(&dirs.data, prefix_str);
        let tmp = dst.with_extension("bin.tmp");
        let bytes = fs::read(&src).await?;
        let digest = crate::digest::compute(&bytes);
        fs::copy(&src, &tmp).await?;
        fs::rename(&tmp, &dst).await?;
        crate::digest::write(&dirs.digests, prefix, &digest).await?;
    }

    let prefix_strings: Vec<CompactString> = changed_prefixes
        .iter()
        .map(|&p| {
            let hex = prefix_to_hex(p);
            // SAFETY: prefix_to_hex produces only uppercase ASCII hex digits (0-9, A-F).
            CompactString::new(unsafe { std::str::from_utf8_unchecked(&hex) })
        })
        .collect();

    let prev_last_updated = state.read().unwrap().sync.last_updated;
    let new_timestamp = Utc::now();

    let new_changed = ChangedState { prev_last_updated, prefixes: prefix_strings };
    let new_sync =
        SyncState { last_updated: Some(new_timestamp), last_checked: Some(new_timestamp) };

    save_changed(&dirs.base, &new_changed).await?;
    save_sync(&dirs.base, &new_sync).await?;

    {
        let mut guard = state.write().unwrap();
        guard.sync = new_sync;
        guard.changed = new_changed;
    }

    clear_staging(&dirs.staging).await?;

    tracing::info!(count = changed_prefixes.len(), "committed changed prefixes");
    Ok(())
}

#[tracing::instrument]
async fn enumerate_staging_bin_files(staging_dir: &Path) -> Result<Vec<u32>, Error> {
    let mut prefixes = Vec::new();
    let mut entries = fs::read_dir(staging_dir).await?;
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
            prefixes.push(p);
        }
    }
    Ok(prefixes)
}

async fn has_bin_files(dir: &Path) -> Result<bool, Error> {
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.path().extension().is_some_and(|e| e == "bin") {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn clear_staging(staging_dir: &Path) -> Result<(), Error> {
    fs::remove_dir_all(staging_dir).await?;
    fs::create_dir_all(staging_dir).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use super::*;
    use crate::serve::state::ServerState;

    fn make_dirs(base: &std::path::Path) -> Dirs {
        let dirs = Dirs::new(base.to_path_buf());
        std::fs::create_dir_all(&dirs.data).unwrap();
        std::fs::create_dir_all(&dirs.digests).unwrap();
        std::fs::create_dir_all(&dirs.staging).unwrap();
        dirs
    }

    fn write_fake_bin(dir: &std::path::Path, stem: &str) {
        std::fs::write(dir.join(format!("{}.bin", stem)), b"fake").unwrap();
    }

    fn staging_has_bins(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir)
            .unwrap()
            .any(|e| e.unwrap().path().extension().is_some_and(|x| x == "bin"))
    }

    #[tokio::test]
    async fn recover_empty_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        assert!(!staging_has_bins(&dirs.staging));
        assert!(!dirs.data.join("00001.bin").exists());
        assert!(state.read().unwrap().sync.last_updated.is_none());
    }

    #[tokio::test]
    async fn recover_complete_marker_present() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        write_fake_bin(&dirs.staging, "00001");
        write_fake_bin(&dirs.staging, "00002");
        std::fs::write(dirs.staging.join(".complete"), b"").unwrap();

        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        assert!(dirs.data.join("00001.bin").exists());
        assert!(dirs.data.join("00002.bin").exists());
        assert!(!staging_has_bins(&dirs.staging));
        assert!(dirs.base.join("state.json").exists());
        assert!(state.read().unwrap().sync.last_updated.is_some());
    }

    #[tokio::test]
    async fn recover_no_complete_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        write_fake_bin(&dirs.staging, "00001");
        write_fake_bin(&dirs.staging, "00002");

        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        assert!(!staging_has_bins(&dirs.staging));
        assert!(!dirs.data.join("00001.bin").exists());
        assert!(state.read().unwrap().sync.last_updated.is_none());
    }

    #[tokio::test]
    async fn recover_stale_complete_marker_without_bins() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        std::fs::write(dirs.staging.join(".complete"), b"").unwrap();
        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        assert!(!dirs.staging.join(".complete").exists());
    }

    #[tokio::test]
    async fn recover_discard_keeps_existing_digests() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        let prefix = 0x00001u32;
        let old_digest = [7u8; 32];
        crate::digest::write(&dirs.digests, prefix, &old_digest).await.unwrap();

        write_fake_bin(&dirs.staging, "00001");
        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        assert!(!dirs.data.join("00001.bin").exists());
        let got = crate::digest::read(&dirs.digests, prefix).await.unwrap();
        assert_eq!(got, Some(old_digest));
    }

    #[tokio::test]
    async fn finish_commit_updates_digest_from_committed_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));

        let prefix = 0x00001u32;
        let prefix_hex = crate::conversion::prefix_to_hex(prefix);
        let prefix_str = std::str::from_utf8(&prefix_hex).unwrap();
        let staged_bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        std::fs::write(
            crate::worker::bin_path(&dirs.staging, prefix_str),
            &staged_bytes,
        )
        .unwrap();
        std::fs::write(dirs.staging.join(".complete"), b"").unwrap();

        recover_if_needed(&dirs, Arc::clone(&state)).await.unwrap();

        let committed = std::fs::read(crate::worker::bin_path(&dirs.data, prefix_str)).unwrap();
        assert_eq!(committed, staged_bytes);
        let expected = crate::digest::compute(&staged_bytes);
        let got = crate::digest::read(&dirs.digests, prefix).await.unwrap();
        assert_eq!(got, Some(expected));
    }

    #[tokio::test]
    async fn run_download_cycle_rejects_zero_workers() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = make_dirs(tmp.path());
        let state = Arc::new(RwLock::new(ServerState::default()));
        let client = reqwest::Client::new();

        let err = run_download_cycle(&dirs, &client, 0, state).await.unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
