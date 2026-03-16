# hibp-sync-client

[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/hibp-rs/ci.yml?branch=main)](https://github.com/PrismaPhonic/hibp-rs/actions)
[![crates.io](https://img.shields.io/crates/v/hibp-sync-client.svg)](https://crates.io/crates/hibp-sync-client)
[![docs.rs](https://docs.rs/hibp-sync-client/badge.svg)](https://docs.rs/hibp-sync-client)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/hibp-rs)

Syncs a local HIBP sha1t48 dataset from an [hibp-bin-fetch](https://crates.io/crates/hibp-bin-fetch)
serve instance, with support for full syncs, delta syncs, and crash-safe resumption.

This is the client counterpart to `hibp-bin-fetch serve`. Use it to keep a local replica of
the HIBP dataset up to date, then check passwords against it with
[hibp-verifier](https://crates.io/crates/hibp-verifier).

## Features

- Full sync on first run, delta sync on subsequent runs
- Segmented sequential downloads with configurable resume granularity
- Automatic fallback from delta to full sync when the server has advanced multiple cycles
- Crash-safe: interrupted syncs resume where they left off; stale staging is discarded if the
  server has moved on

## Installation

```sh
cargo install hibp-sync-client
```

## Usage

First, ensure an `hibp-bin-fetch serve` instance is running:

```sh
hibp-bin-fetch serve --data-dir /var/lib/hibp-sync --listen 0.0.0.0:8765
```

Then run the sync client against it:

```sh
hibp-sync-client --server-url http://192.168.1.10:8765 --data-dir ./hibp-data
```

### Options

| Flag              | Description                                          |
|-------------------|------------------------------------------------------|
| `--server-url`    | URL of the hibp-bin-fetch serve instance (required)  |
| `--data-dir`      | Directory where .bin files are stored (required)     |
| `--segments`      | Number of segments to split the sync into (default: 16) |
| `--log-level`     | Log verbosity: error, warn, info, debug, trace       |

## Sync Modes

### Full Sync

On first run (no local dataset), the server divides the entire 1,048,576-prefix dataset
into `--segments` zstd-compressed chunks. The client fetches them sequentially, unpacking
each segment and writing the prefix files to a staging directory before atomically moving
them to the data directory.

### Delta Sync

On subsequent runs the client checks whether the server's `prev_last_updated` timestamp
matches the local `last_updated`. If it does, only the prefixes that changed in the
server's most recent nightly cycle are transferred - typically a few thousand files rather
than the full 1 million. If the server has advanced more than one cycle the client falls
back to a full sync automatically.

## Crash-Safe Design

Downloads are staged in `.staging/` within the data directory. Each segment is marked
complete with a sentinel file once written, so a restart skips already-finished segments.
After all segments are done a `.complete` marker is written; the next run will finish the
atomic move even if the process died before the commit completed. If the server's data
has changed since staging began, the stale staging directory is discarded and a fresh
sync starts.

## Library Usage

The `sync` function can be called directly when embedding sync logic in a larger
application:

```rust,ignore
use hibp_sync_client::sync::{Config, Outcome, sync};
use std::path::PathBuf;
use url::Url;

let config = Config {
    server_url: Url::parse("http://192.168.1.10:8765").unwrap(),
    data_dir: PathBuf::from("./hibp-data"),
    segments: 16,
};

match sync(&config).await? {
    Outcome::UpToDate => println!("already up to date"),
    Outcome::DeltaSync { changed_count } => println!("{changed_count} files updated"),
    Outcome::FullSync { file_count } => println!("{file_count} files written"),
}
```

## Related Projects

- [hibp-bin-fetch](https://crates.io/crates/hibp-bin-fetch) - Downloads the HIBP dataset and runs the serve instance this client connects to
- [hibp-verifier](https://crates.io/crates/hibp-verifier) - Checks passwords against the synced dataset

## License

MIT
