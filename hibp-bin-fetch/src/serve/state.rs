use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use tokio::fs;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SyncState {
    pub last_updated: Option<DateTime<Utc>>,
    pub last_checked: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ChangedState {
    pub prev_last_updated: Option<DateTime<Utc>>,
    pub prefixes: Vec<CompactString>,
}

#[derive(Default, Clone)]
pub struct ServerState {
    pub sync: SyncState,
    pub changed: ChangedState,
}

impl ServerState {
    pub async fn load(base_dir: &Path) -> io::Result<Self> {
        let sync = load_json(base_dir.join("state.json")).await?.unwrap_or_default();
        let changed = load_json(base_dir.join("changed.json")).await?.unwrap_or_default();
        Ok(Self { sync, changed })
    }
}

pub async fn save_sync(base_dir: &Path, state: &SyncState) -> io::Result<()> {
    write_json_atomic(base_dir.join("state.json"), state).await
}

pub async fn save_changed(base_dir: &Path, state: &ChangedState) -> io::Result<()> {
    write_json_atomic(base_dir.join("changed.json"), state).await
}

async fn load_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> io::Result<Option<T>> {
    match fs::read(&path).await {
        Ok(bytes) => {
            let value = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

async fn write_json_atomic<T: Serialize>(path: impl AsRef<Path>, value: &T) -> io::Result<()> {
    let path = path.as_ref();
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp, &bytes).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[tokio::test]
    async fn sync_state_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = Utc::now();
        let state = SyncState { last_updated: Some(ts), last_checked: None };
        save_sync(tmp.path(), &state).await.unwrap();
        let loaded = ServerState::load(tmp.path()).await.unwrap();
        assert_eq!(loaded.sync.last_updated, Some(ts));
    }

    #[tokio::test]
    async fn changed_state_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = Utc::now();
        let state = ChangedState {
            prev_last_updated: Some(ts),
            prefixes: vec![CompactString::new("00001"), CompactString::new("ABCDE")],
        };
        save_changed(tmp.path(), &state).await.unwrap();
        let loaded = ServerState::load(tmp.path()).await.unwrap();
        assert_eq!(loaded.changed.prev_last_updated, Some(ts));
        assert_eq!(loaded.changed.prefixes, vec!["00001", "ABCDE"]);
    }

    #[tokio::test]
    async fn missing_files_give_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = ServerState::load(tmp.path()).await.unwrap();
        assert!(loaded.sync.last_updated.is_none());
        assert!(loaded.changed.prev_last_updated.is_none());
        assert!(loaded.changed.prefixes.is_empty());
    }
}
