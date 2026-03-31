use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use async_compression::Level;
use async_compression::tokio::bufread::ZstdEncoder;
use async_stream::try_stream;
use chrono::{DateTime, Utc};
use compact_str::CompactString;
use futures_core::Stream;
use futures_util::StreamExt;
use ntex::web::types::{Query, State};
use ntex::web::{self, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio_util::io::{ReaderStream, StreamReader};

use super::download::Dirs;
use super::error::ApiError;
use super::state::ServerState;
use crate::TOTAL_PREFIXES;
use crate::conversion::prefix_to_hex;

#[derive(Clone)]
pub struct AppState {
    pub server_state: Arc<RwLock<ServerState>>,
    pub dirs: Arc<Dirs>,
}

#[derive(Serialize)]
struct Status {
    last_updated: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct Changed {
    last_updated: Option<DateTime<Utc>>,
    prev_last_updated: Option<DateTime<Utc>>,
    prefixes: Vec<CompactString>,
}

#[derive(Deserialize)]
pub struct SegmentQuery {
    segment: u8,
    of: u8,
    since: Option<String>,
}

#[web::get("/v1/status")]
#[tracing::instrument(skip_all)]
pub async fn get_status(state: State<AppState>) -> HttpResponse {
    let last_updated = state.server_state.read().unwrap().sync.last_updated;
    HttpResponse::Ok().json(&Status { last_updated })
}

#[web::get("/v1/changed")]
#[tracing::instrument(skip_all)]
pub async fn get_changed(state: State<AppState>) -> HttpResponse {
    let guard = state.server_state.read().unwrap();
    let body = Changed {
        last_updated: guard.sync.last_updated,
        prev_last_updated: guard.changed.prev_last_updated,
        prefixes: guard.changed.prefixes.clone(),
    };
    drop(guard);
    HttpResponse::Ok().json(&body)
}

#[web::get("/v1/segment")]
#[tracing::instrument(skip_all, fields(segment = query.segment, of = query.of))]
pub async fn get_segment(
    state: State<AppState>,
    query: Query<SegmentQuery>,
) -> Result<HttpResponse, ApiError> {
    let segment = query.segment as usize;
    let of = query.of as usize;

    if of == 0 || segment >= of {
        tracing::warn!(segment, of, "invalid segment parameters");
        return Err(ApiError::InvalidSegmentParams);
    }

    let stream = if let Some(ref since_str) = query.since {
        let since_ts = since_str.parse::<DateTime<Utc>>().map_err(|_| {
            tracing::warn!(since = %since_str, "invalid since timestamp");
            ApiError::InvalidSinceTimestamp
        })?;

        let mut all_changed: Vec<u32> = {
            let guard = state.server_state.read().unwrap();
            if guard.changed.prev_last_updated != Some(since_ts) {
                tracing::warn!(
                    since = %since_str,
                    prev_last_updated = ?guard.changed.prev_last_updated,
                    "not one cycle behind"
                );
                return Err(ApiError::NotOneCycleBehind);
            }
            guard
                .changed
                .prefixes
                .iter()
                .filter_map(|s| u32::from_str_radix(s, 16).ok())
                .collect()
        };
        all_changed.sort_unstable();
        let (start, end) = segment_bounds(all_changed.len(), segment, of);
        encode_prefix_list(state.dirs.clone(), all_changed[start..end].to_vec())
    } else {
        let (start, end) = segment_bounds(TOTAL_PREFIXES as usize, segment, of);
        encode_segment(state.dirs.clone(), start as u32, end as u32)
    };

    tracing::info!("segment stream started");
    Ok(HttpResponse::Ok().content_type("application/octet-stream").streaming(stream))
}

#[web::get("/healthz")]
#[tracing::instrument(skip_all)]
pub async fn healthz(state: State<AppState>) -> HttpResponse {
    let last_checked = state.server_state.read().unwrap().sync.last_checked;
    let healthy = match last_checked {
        None => true,
        Some(ts) => Utc::now().signed_duration_since(ts).num_hours() < 30,
    };
    if healthy {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::ServiceUnavailable().finish()
    }
}

fn segment_bounds(total: usize, segment: usize, of: usize) -> (usize, usize) {
    let chunk_size = total.div_ceil(of);
    let start = (segment * chunk_size).min(total);
    let end = start.saturating_add(chunk_size).min(total);
    (start, end)
}

pub(crate) fn encode_segment(
    dirs: Arc<Dirs>,
    start: u32,
    end: u32,
) -> Pin<Box<dyn Stream<Item = Result<ntex::util::Bytes, io::Error>> + Send>> {
    Box::pin(encode_impl(dirs, (end - start) as usize, start..end))
}

pub(crate) fn encode_prefix_list(
    dirs: Arc<Dirs>,
    prefixes: Vec<u32>,
) -> Pin<Box<dyn Stream<Item = Result<ntex::util::Bytes, io::Error>> + Send>> {
    Box::pin(encode_impl(dirs, prefixes.len(), prefixes.into_iter()))
}

fn encode_impl(
    dirs: Arc<Dirs>,
    count: usize,
    iter: impl Iterator<Item = u32> + Send + 'static,
) -> impl Stream<Item = Result<ntex::util::Bytes, io::Error>> + Send + 'static {
    let uncompressed_stream = try_stream! {
        yield ntex::util::Bytes::copy_from_slice(&(count as u32).to_le_bytes());
        for prefix in iter {
            let hex = prefix_to_hex(prefix);
            // SAFETY: prefix_to_hex produces only uppercase ASCII hex digits (0-9, A-F).
            let prefix_str = unsafe { std::str::from_utf8_unchecked(&hex) };
            let path = crate::worker::bin_path(&dirs.data, prefix_str);

            let content = match tokio::fs::read(&path).await {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    tracing::error!(
                        ?path,
                        "CRITICAL: missing data file! Server state is corrupted. Crashing."
                    );
                    std::process::exit(1);
                }
                Err(e) => Err(e)?,
            };

            yield ntex::util::Bytes::copy_from_slice(&hex);
            yield ntex::util::Bytes::copy_from_slice(&(content.len() as u32).to_le_bytes());
            yield ntex::util::Bytes::from(content);
        }
    };

    let uncompressed_stream: Pin<
        Box<dyn Stream<Item = Result<ntex::util::Bytes, io::Error>> + Send>,
    > = Box::pin(uncompressed_stream);

    let reader = StreamReader::new(uncompressed_stream);
    let encoder = ZstdEncoder::with_quality(reader, Level::Precise(3));
    ReaderStream::new(encoder).map(|res| res.map(|b| ntex::util::Bytes::copy_from_slice(&b)))
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::serve::download::Dirs;

    #[test]
    fn segment_bounds_even() {
        assert_eq!(segment_bounds(100, 0, 4), (0, 25));
        assert_eq!(segment_bounds(100, 1, 4), (25, 50));
        assert_eq!(segment_bounds(100, 2, 4), (50, 75));
        assert_eq!(segment_bounds(100, 3, 4), (75, 100));
    }

    #[test]
    fn segment_bounds_uneven() {
        // div_ceil(101, 4) = 26
        assert_eq!(segment_bounds(101, 0, 4), (0, 26));
        assert_eq!(segment_bounds(101, 1, 4), (26, 52));
        assert_eq!(segment_bounds(101, 2, 4), (52, 78));
        assert_eq!(segment_bounds(101, 3, 4), (78, 101));
    }

    #[test]
    fn segment_bounds_single() {
        assert_eq!(segment_bounds(50, 0, 1), (0, 50));
    }

    #[test]
    fn segment_bounds_last_gets_remainder() {
        // div_ceil(10, 3) = 4; s2: start=8, end=min(12,10)=10
        assert_eq!(segment_bounds(10, 2, 3), (8, 10));
    }

    #[tokio::test]
    async fn encode_decode_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Arc::new(Dirs::new(tmp.path().to_path_buf()));
        tokio::fs::create_dir_all(&dirs.data).await.unwrap();

        let prefixes = [0x00001u32, 0x00002u32, 0x000FFu32];
        let contents: Vec<Vec<u8>> = prefixes.iter().map(|&p| vec![p as u8; 12]).collect();

        for (&p, content) in prefixes.iter().zip(contents.iter()) {
            let hex = crate::conversion::prefix_to_hex(p);
            let name = std::str::from_utf8(&hex).unwrap();
            tokio::fs::write(dirs.data.join(format!("{}.bin", name)), content)
                .await
                .unwrap();
        }

        let stream = encode_prefix_list(dirs.clone(), prefixes.to_vec());
        let mut stream = Box::pin(stream);
        let mut result = Vec::new();
        while let Some(chunk) = stream.next().await {
            result.extend_from_slice(&chunk.unwrap());
        }

        let decompressed = zstd::decode_all(&result[..]).unwrap();

        let count = u32::from_le_bytes(decompressed[..4].try_into().unwrap()) as usize;
        assert_eq!(count, prefixes.len());

        let mut pos = 4;
        let mut decoded: Vec<(u32, Vec<u8>)> = Vec::new();
        for _ in 0..count {
            let prefix_bytes: [u8; 5] = decompressed[pos..pos + 5].try_into().unwrap();
            pos += 5;
            let len = u32::from_le_bytes(decompressed[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let content = decompressed[pos..pos + len].to_vec();
            pos += len;
            let p = u32::from_str_radix(std::str::from_utf8(&prefix_bytes).unwrap(), 16).unwrap();
            decoded.push((p, content));
        }

        let expected: Vec<(u32, Vec<u8>)> =
            prefixes.iter().zip(contents.iter()).map(|(&p, c)| (p, c.clone())).collect();
        assert_eq!(decoded, expected);
    }
}
