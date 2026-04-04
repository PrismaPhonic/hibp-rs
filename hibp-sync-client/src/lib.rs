//! Syncs a local HIBP sha1t48 dataset from an
//! [hibp-bin-fetch](https://crates.io/crates/hibp-bin-fetch) serve instance, with
//! support for full syncs, delta syncs, and crash-safe resumption.
//!
//! This is the client counterpart to `hibp-bin-fetch serve`. It runs as a persistent
//! daemon, waking once per night at a configurable UTC time to pull whichever prefix files
//! have changed since the last sync, or all of them on first run. The resulting dataset is
//! compatible with [hibp-verifier](https://crates.io/crates/hibp-verifier) for
//! sub-microsecond password breach checking.
//!
//! # Nightly Schedule
//!
//! The daemon sleeps until the configured `--sync-at` time (UTC, default `04:00`), runs a
//! sync cycle, then sleeps until the same time the following day. Set `--sync-at` to a time
//! comfortably after the server's `--download-at` time so the server has finished its own
//! nightly download before the client requests changes. A sync failure is logged as an error
//! but does not exit the process - the client waits for the next scheduled cycle.
//!
//! Pass `--sync-on-start` to run an immediate sync cycle before entering the nightly
//! schedule, which is useful on first deployment or after an extended outage.
//!
//! # Sync Modes
//!
//! ## Full Sync
//!
//! On first run (no local dataset yet), every prefix file is fetched from the server.
//! The server divides the full dataset into `--segments` chunks and the client fetches
//! them sequentially, decompressing each segment and writing the prefix files to a staging
//! directory before atomically moving them to the data directory.
//!
//! ## Delta Sync
//!
//! After each successful sync the client writes the server's `last_updated` timestamp
//! to a local state file. This timestamp acts as a version identifier. On the next run,
//! the client asks the server for its `prev_last_updated` - the timestamp of the cycle
//! immediately before the current one. If that matches the locally stored timestamp, the
//! client is exactly one cycle behind and only the changed prefixes need to be fetched.
//!
//! If the timestamps do not match (e.g. the client has been offline for multiple nightly
//! cycles and the server has since moved on), delta sync is not possible and the client
//! falls back to a full sync automatically.
//!
//! # Crash-Safe Design
//!
//! All downloads land in a `.staging/` subdirectory of the data directory before being
//! committed. If the process is interrupted mid-download, the next run resumes from where
//! it left off - completed segments are not re-fetched. If the server's data has changed
//! between attempts, the stale staging directory is discarded and a fresh sync starts.
//!
//! # Usage
//!
//! First, ensure an `hibp-bin-fetch serve` instance is running and accessible.
//!
//! ## CLI
//!
//! Run as a persistent daemon (syncs nightly at 04:00 UTC by default):
//!
//! ```sh
//! hibp-sync-client --server-url http://192.168.1.10:8765 --data-dir ./hibp-data
//! ```
//!
//! Sync immediately on startup, then continue on the nightly schedule:
//!
//! ```sh
//! hibp-sync-client --server-url http://192.168.1.10:8765 --data-dir ./hibp-data --sync-on-start
//! ```
//!
//! Sync at a custom time and with finer resume granularity:
//!
//! ```sh
//! hibp-sync-client --server-url http://192.168.1.10:8765 --data-dir ./hibp-data \
//!     --sync-at 05:30 --segments 32
//! ```
//!
//! ## Library
//!
//! ```rust,ignore
//! use hibp_sync_client::sync::{Config, Outcome, sync};
//! use std::path::PathBuf;
//!
//! let config = Config {
//!     server_url: "http://192.168.1.10:8765".parse().unwrap(),
//!     data_dir: PathBuf::from("./hibp-data"),
//!     segments: 16,
//! };
//!
//! match sync(&config).await? {
//!     Outcome::UpToDate => println!("already up to date"),
//!     Outcome::DeltaSync { changed_count } => println!("{changed_count} files updated"),
//!     Outcome::FullSync { file_count } => println!("{file_count} files written"),
//! }
//! ```

pub mod client;
pub mod error;
pub mod sync;
pub mod wire;
