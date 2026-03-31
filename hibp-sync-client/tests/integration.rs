use std::path::Path;

use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use hibp_sync_client::sync::{Config, Outcome, sync};
use http::Uri;
use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

async fn http_get_status(url: &str) -> u16 {
    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let uri: Uri = url.parse().unwrap();
    let resp = client
        .request(hyper::Request::get(uri).body(Empty::new()).unwrap())
        .await
        .unwrap();
    resp.status().as_u16()
}

// Fixed timestamps used across tests. Z-suffix format is URL-safe and matches what sync.rs writes.
const T0: &str = "2026-01-01T00:00:00Z";
const T1: &str = "2026-01-01T01:00:00Z";
const T2: &str = "2026-01-01T02:00:00Z";

// 16 small prefixes used as the test dataset.
const PREFIXES: &[u32] = &[
    0x00000, 0x00001, 0x00002, 0x00003, 0x00004, 0x00005, 0x00006, 0x00007, 0x00008, 0x00009,
    0x0000A, 0x0000B, 0x0000C, 0x0000D, 0x0000E, 0x0000F,
];

fn ts(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339).unwrap().with_timezone(&Utc)
}

fn hex_prefix(p: u32) -> String {
    format!("{:05X}", p)
}

// Deterministic 18-byte content (3 sorted 6-byte records) seeded from prefix+version.
fn fake_bin(prefix: u32, version: u32) -> Vec<u8> {
    let seed = (prefix as u64) << 32 | version as u64;
    let mut state = seed;
    let mut records: Vec<[u8; 6]> = (0..3)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let b = state.to_le_bytes();
            [b[2], b[3], b[4], b[5], b[6], b[7]]
        })
        .collect();
    records.sort();
    records.iter().flatten().copied().collect()
}

fn prepare_dirs(base: &Path) {
    std::fs::create_dir_all(base.join("data")).unwrap();
    std::fs::create_dir_all(base.join("digests")).unwrap();
    std::fs::create_dir_all(base.join("staging")).unwrap();
}

fn write_bins(dir: &Path, prefixes: &[u32], version: u32) {
    std::fs::create_dir_all(dir).unwrap();
    for &p in prefixes {
        std::fs::write(
            dir.join(format!("{}.bin", hex_prefix(p))),
            fake_bin(p, version),
        )
        .unwrap();
    }
}

#[derive(Serialize)]
struct ServerStateFile {
    last_updated: DateTime<Utc>,
}

#[derive(Serialize)]
struct ServerStateCheckedFile {
    last_checked: DateTime<Utc>,
}

#[derive(Serialize)]
struct ChangedStateFile {
    prev_last_updated: Option<DateTime<Utc>>,
    prefixes: Vec<String>,
}

#[derive(Serialize)]
struct ClientStateFile {
    last_updated: DateTime<Utc>,
}

#[derive(Serialize)]
struct PlanFile<'a> {
    server_last_updated: DateTime<Utc>,
    since: Option<&'a str>,
    segments: usize,
}

fn write_server_state(base: &Path, last_updated: DateTime<Utc>) {
    let s = ServerStateFile { last_updated };
    std::fs::write(base.join("state.json"), serde_json::to_vec(&s).unwrap()).unwrap();
}

fn write_server_checked(base: &Path, last_checked: DateTime<Utc>) {
    let s = ServerStateCheckedFile { last_checked };
    std::fs::write(base.join("state.json"), serde_json::to_vec(&s).unwrap()).unwrap();
}

fn write_changed(base: &Path, prev: Option<DateTime<Utc>>, prefixes: &[u32]) {
    let s = ChangedStateFile {
        prev_last_updated: prev,
        prefixes: prefixes.iter().map(|&p| hex_prefix(p)).collect(),
    };
    std::fs::write(base.join("changed.json"), serde_json::to_vec(&s).unwrap()).unwrap();
}

fn write_client_state(data_dir: &Path, last_updated: DateTime<Utc>) {
    let s = ClientStateFile { last_updated };
    std::fs::write(
        data_dir.join("sync-state.json"),
        serde_json::to_vec(&s).unwrap(),
    )
    .unwrap();
}

fn write_sync_plan(
    staging: &Path,
    server_last_updated: DateTime<Utc>,
    since: Option<&str>,
    segments: usize,
) {
    let s = PlanFile { server_last_updated, since, segments };
    std::fs::write(
        staging.join(".sync-plan.json"),
        serde_json::to_vec(&s).unwrap(),
    )
    .unwrap();
}

// Starts the server in a dedicated OS thread with ntex's own system context.
// ntex::HttpServer is not Send, so it cannot be tokio::spawn'd; it must run
// in a thread where ntex::rt::System has been set up.
// The server keeps running until the test process exits;
// ephemeral ports ensure no cross-test conflicts.
async fn start_server(base: &Path) -> Uri {
    use hibp_bin_fetch::serve::{LogLevel, ServeArgs};
    let (tx, rx) = tokio::sync::oneshot::channel();
    let data_dir = base.to_path_buf();
    std::thread::spawn(move || {
        ntex::rt::System::new("test", ntex::rt::DefaultRuntime)
            .block_on(hibp_bin_fetch::serve::run(
                ServeArgs {
                    data_dir,
                    listen: "127.0.0.1:0".parse().unwrap(),
                    concurrent_workers: 2,
                    download_at: "03:00".parse().unwrap(),
                    download_on_start: false,
                    log_level: LogLevel::Warn,
                },
                Some(tx),
            ))
            .ok();
    });
    let addr = rx.await.expect("server failed to start");
    format!("http://{addr}").parse().unwrap()
}

fn sync_cfg(server_url: Uri, data_dir: &Path, segments: u8) -> Config {
    Config { server_url, data_dir: data_dir.to_path_buf(), segments }
}

// Server has no state.json → status returns last_updated:null → UpToDate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_data_yet() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();
    let url = start_server(srv.path()).await;

    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::UpToDate));
}

// Client at T0, server at T1 with all 16 prefixes in changed list → DeltaSync{16}.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_sync() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    write_server_state(srv.path(), ts(T1));
    write_changed(srv.path(), Some(ts(T0)), PREFIXES);
    write_client_state(cli.path(), ts(T0));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::DeltaSync { changed_count: 16 }));

    for &p in PREFIXES {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(content, fake_bin(p, 1), "prefix {p:#07X} had wrong content");
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cli.path().join("sync-state.json")).unwrap())
            .unwrap();
    let saved_ts: DateTime<Utc> = serde_json::from_value(saved["last_updated"].clone()).unwrap();
    assert_eq!(saved_ts, ts(T1));
}

// Client already at T1, server at T1 → UpToDate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn already_up_to_date() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_server_state(srv.path(), ts(T1));
    write_client_state(cli.path(), ts(T1));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::UpToDate));
}

// Client at T1, server at T2 with 4 of 16 prefixes changed → DeltaSync{4}, 4 files updated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_sync_partial_update() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    let changed: &[u32] = &[0x00000, 0x00005, 0x0000A, 0x0000F];

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    for &p in changed {
        std::fs::write(
            srv.path().join("data").join(format!("{}.bin", hex_prefix(p))),
            fake_bin(p, 2),
        )
        .unwrap();
    }
    write_server_state(srv.path(), ts(T2));
    write_changed(srv.path(), Some(ts(T1)), changed);

    write_bins(cli.path(), PREFIXES, 1);
    write_client_state(cli.path(), ts(T1));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::DeltaSync { changed_count: 4 }));

    for &p in changed {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(
            content,
            fake_bin(p, 2),
            "changed prefix {p:#07X} not updated"
        );
    }
    let unchanged: Vec<u32> = PREFIXES.iter().copied().filter(|p| !changed.contains(p)).collect();
    for p in unchanged {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(
            content,
            fake_bin(p, 1),
            "unchanged prefix {p:#07X} was modified"
        );
    }
}

// Client staging has .complete + all 16 .bin files → commits without contacting server.
#[tokio::test]
async fn client_crash_recovery_interrupted_commit() {
    let cli = tempfile::tempdir().unwrap();
    let staging = cli.path().join(".staging");
    std::fs::create_dir_all(&staging).unwrap();

    write_sync_plan(&staging, ts(T1), None, 1);
    std::fs::write(staging.join(".complete"), b"").unwrap();
    write_bins(&staging, PREFIXES, 1);

    // Dummy server URL - will not be contacted.
    let config = sync_cfg("http://127.0.0.1:1".parse().unwrap(), cli.path(), 1);
    let outcome = sync(&config).await.unwrap();
    assert!(matches!(outcome, Outcome::FullSync { file_count: 16 }));

    for &p in PREFIXES {
        assert!(cli.path().join(format!("{}.bin", hex_prefix(p))).exists());
    }
    assert!(!staging.exists());

    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cli.path().join("sync-state.json")).unwrap())
            .unwrap();
    let saved_ts: DateTime<Utc> = serde_json::from_value(saved["last_updated"].clone()).unwrap();
    assert_eq!(saved_ts, ts(T1));
}

// Client staging has partial delta download (segment 0 done, segment 1 missing).
// sync() re-fetches only segment 1 then commits all 16 files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_crash_recovery_partial_download() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    // Server: T1, all 16 prefixes changed from T0.
    // PREFIXES are sorted; with segments=2: segment 0 = first 8, segment 1 = last 8.
    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    write_server_state(srv.path(), ts(T1));
    write_changed(srv.path(), Some(ts(T0)), PREFIXES);

    let url = start_server(srv.path()).await;

    // Client staging: delta plan (since=T0, segments=2), segment 0 already done.
    let staging = cli.path().join(".staging");
    std::fs::create_dir_all(&staging).unwrap();
    write_sync_plan(&staging, ts(T1), Some(T0), 2);
    std::fs::write(staging.join(".seg.0.done"), b"").unwrap();
    write_bins(&staging, &PREFIXES[..8], 1);

    let outcome = sync(&sync_cfg(url, cli.path(), 2)).await.unwrap();
    assert!(matches!(outcome, Outcome::DeltaSync { changed_count: 16 }));

    for &p in PREFIXES {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(content, fake_bin(p, 1));
    }
}

// Server staging has .bin files but no .complete -> recovery discards staging, data stays empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_recovery_no_complete_marker() {
    let srv = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("staging"), PREFIXES, 1);

    // By the time start_server returns, recover_if_needed has already run.
    let _url = start_server(srv.path()).await;

    for &p in PREFIXES {
        assert!(
            !srv.path().join("data").join(format!("{}.bin", hex_prefix(p))).exists(),
            "prefix {p:#07X} should not be in data/ after discard"
        );
    }
    assert!(!srv.path().join("state.json").exists());
}

// Server staging has .bin files + .complete → recovery commits them into data/.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_recovery_complete_marker_present() {
    let srv = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("staging"), PREFIXES, 1);
    std::fs::write(srv.path().join("staging").join(".complete"), b"").unwrap();

    let _url = start_server(srv.path()).await;

    for &p in PREFIXES {
        assert!(
            srv.path().join("data").join(format!("{}.bin", hex_prefix(p))).exists(),
            "prefix {p:#07X} missing from data/ after recovery commit"
        );
    }
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(srv.path().join("state.json")).unwrap()).unwrap();
    assert!(!state["last_updated"].is_null());
}

// /healthz returns 200 when no download has run yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_no_data() {
    let srv = tempfile::tempdir().unwrap();
    let url = start_server(srv.path()).await;

    let status = http_get_status(&format!("{}healthz", url)).await;
    assert_eq!(status, 200);
}

// /healthz returns 200 when last_checked is within 30 hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_healthy() {
    let srv = tempfile::tempdir().unwrap();
    prepare_dirs(srv.path());
    write_server_checked(srv.path(), Utc::now() - TimeDelta::hours(1));

    let url = start_server(srv.path()).await;
    let status = http_get_status(&format!("{}healthz", url)).await;
    assert_eq!(status, 200);
}

// /healthz returns 503 when last_checked is more than 30 hours ago.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_stale() {
    let srv = tempfile::tempdir().unwrap();
    prepare_dirs(srv.path());
    write_server_checked(srv.path(), Utc::now() - TimeDelta::hours(31));

    let url = start_server(srv.path()).await;
    let status = http_get_status(&format!("{}healthz", url)).await;
    assert_eq!(status, 503);
}

// /healthz returns 503 at exactly 30 hours (boundary is < 30, not <= 30).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_boundary() {
    let srv = tempfile::tempdir().unwrap();
    prepare_dirs(srv.path());
    write_server_checked(srv.path(), Utc::now() - TimeDelta::hours(30));

    let url = start_server(srv.path()).await;
    let status = http_get_status(&format!("{}healthz", url)).await;
    assert_eq!(status, 503);
}

// No sync-state.json, server has data → FullSync{16}.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_sync_from_scratch() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    write_server_state(srv.path(), ts(T1));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::FullSync { file_count: 16 }));

    for &p in PREFIXES {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(content, fake_bin(p, 1));
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cli.path().join("sync-state.json")).unwrap())
            .unwrap();
    let saved_ts: DateTime<Utc> = serde_json::from_value(saved["last_updated"].clone()).unwrap();
    assert_eq!(saved_ts, ts(T1));
}

// Client is two cycles behind (T0, server moved T1→T2) → changed.prev(T1) != local(T0) → FullSync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_fallback_to_full() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 2);
    write_server_state(srv.path(), ts(T2));
    write_changed(srv.path(), Some(ts(T1)), PREFIXES);

    write_client_state(cli.path(), ts(T0));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::FullSync { file_count: 16 }));
}

// GET /v1/segment?since=T0 when server prev_last_updated=T1 → 409.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_409_when_since_mismatch() {
    let srv = tempfile::tempdir().unwrap();

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    write_server_state(srv.path(), ts(T2));
    write_changed(srv.path(), Some(ts(T1)), PREFIXES);

    let url = start_server(srv.path()).await;
    let status = http_get_status(&format!("{}v1/segment?segment=0&of=1&since={}", url, T0)).await;
    assert_eq!(status, 409);
}

// Staging has a plan for T1, partial bins, no .complete; server has moved to T2.
// sync() detects the stale plan, discards staging, and performs a fresh delta sync (T1→T2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_resume_detects_stale_plan() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    let changed: &[u32] = &[0x00000, 0x00005, 0x0000A, 0x0000F];

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    for &p in changed {
        std::fs::write(
            srv.path().join("data").join(format!("{}.bin", hex_prefix(p))),
            fake_bin(p, 2),
        )
        .unwrap();
    }
    write_server_state(srv.path(), ts(T2));
    write_changed(srv.path(), Some(ts(T1)), changed);

    // Client is at T1; staging has a stale plan also targeting T1 but the server is now at T2.
    write_client_state(cli.path(), ts(T1));
    let staging = cli.path().join(".staging");
    std::fs::create_dir_all(&staging).unwrap();
    write_sync_plan(&staging, ts(T1), Some(T1), 1);
    write_bins(&staging, &PREFIXES[..4], 1);

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 1)).await.unwrap();
    assert!(matches!(outcome, Outcome::DeltaSync { changed_count: 4 }));

    for &p in changed {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(
            content,
            fake_bin(p, 2),
            "changed prefix {p:#07X} not updated"
        );
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cli.path().join("sync-state.json")).unwrap())
            .unwrap();
    let saved_ts: DateTime<Utc> = serde_json::from_value(saved["last_updated"].clone()).unwrap();
    assert_eq!(saved_ts, ts(T2));
}

// 4 prefixes changed, client uses segments=8 (more segments than changes).
// Some segments will be empty; result is DeltaSync{4}.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_sync_with_more_segments_than_changes() {
    let srv = tempfile::tempdir().unwrap();
    let cli = tempfile::tempdir().unwrap();

    let changed: &[u32] = &[0x00000, 0x00005, 0x0000A, 0x0000F];

    prepare_dirs(srv.path());
    write_bins(&srv.path().join("data"), PREFIXES, 1);
    for &p in changed {
        std::fs::write(
            srv.path().join("data").join(format!("{}.bin", hex_prefix(p))),
            fake_bin(p, 2),
        )
        .unwrap();
    }
    write_server_state(srv.path(), ts(T2));
    write_changed(srv.path(), Some(ts(T1)), changed);

    write_bins(cli.path(), PREFIXES, 1);
    write_client_state(cli.path(), ts(T1));

    let url = start_server(srv.path()).await;
    let outcome = sync(&sync_cfg(url, cli.path(), 8)).await.unwrap();
    assert!(matches!(outcome, Outcome::DeltaSync { changed_count: 4 }));

    for &p in changed {
        let content = std::fs::read(cli.path().join(format!("{}.bin", hex_prefix(p)))).unwrap();
        assert_eq!(
            content,
            fake_bin(p, 2),
            "changed prefix {p:#07X} not updated"
        );
    }
}
