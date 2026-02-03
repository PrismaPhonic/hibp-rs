# hibp-bin-fetch

[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/hibp-rs/ci.yml?branch=main)](https://github.com/PrismaPhonic/hibp-rs/actions)
[![crates.io](https://img.shields.io/crates/v/hibp-bin-fetch.svg)](https://crates.io/crates/hibp-bin-fetch)
[![docs.rs](https://docs.rs/hibp-bin-fetch/badge.svg)](https://docs.rs/hibp-bin-fetch)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/hibp-rs)

Downloads the Have I Been Pwned password hash database and converts it to a
compact 6-byte binary format for use with [hibp-verifier](https://crates.io/crates/hibp-verifier).

**This is not a general-purpose HIBP downloader.** It produces a custom binary
format (sha1t48) specifically designed for fast password breach checking with
`hibp-verifier`. If you need the original HIBP data format, use the official
[Pwned Passwords downloader](https://haveibeenpwned.com/Passwords).

## Features

- Concurrent downloads with configurable worker count
- Direct conversion to compact binary format (no intermediate files)
- Resume support for interrupted downloads
- Progress bar with ETA
- Exponential backoff retry logic for transient failures

## Installation

```sh
cargo install hibp-bin-fetch
```

## Usage

Download the full dataset:

```sh
hibp-bin-fetch --output ./hibp-data
```

With more concurrent workers (default is 64):

```sh
hibp-bin-fetch --output ./hibp-data --concurrent-workers 128
```

Resume an interrupted download:

```sh
hibp-bin-fetch --output ./hibp-data --resume
```

Force overwrite existing data:

```sh
hibp-bin-fetch --output ./hibp-data --force
```

### Options

| Flag                       | Description                                          |
|----------------------------|------------------------------------------------------|
| `-o, --output`             | Output directory for binary files (required)         |
| `-j, --concurrent-workers` | Number of concurrent download workers (default: 64)  |
| `--resume`                 | Skip existing files and continue downloading         |
| `--force`                  | Remove existing output directory before starting     |
| `--limit`                  | Maximum prefix index to download (for testing)       |
| `--no-progress`            | Disable progress bar                                 |

## Binary Format

This tool produces 1,048,576 binary files (one per 5-character hex prefix), each
containing sorted 6-byte records. This format is based on the sha1t64 approach
from [oschonrock/hibp](https://github.com/oschonrock/hibp), but stores only 6
bytes per hash instead of 8. The first 2.5 bytes of each SHA1 hash are encoded
in the filename, so we store only bytes 2-7 (the 6-byte suffix) in each record.

### Why This Format?

The HIBP dataset contains approximately 900 million SHA1 password hashes. Storing
the full 20-byte hash for each entry requires significant space. By truncating to
48 bits (6 bytes), we reduce storage by over 70% while maintaining an acceptably
low collision probability.

With ~900 million entries, the expected number of collisions is less than 1. For
password breach checking, a false positive (incorrectly marking a password as
breached) is harmless—it only causes a user to choose a different password.

### File Layout

Each prefix file (e.g., `00000.bin`, `FFFFF.bin`) contains:

- Fixed 6-byte records (bytes 2-7 of the SHA1 hash)
- Sorted in ascending order
- Direct indexing: record N is at byte offset N * 6

This enables O(log n) binary search with no parsing overhead, which is exactly
what `hibp-verifier` uses for sub-microsecond lookups.

### Storage Comparison

| Format               | Size  | Notes               |
|----------------------|-------|---------------------|
| HIBP Text (original) | 77 GB | SHA1:count per line |
| sha1t48 binary       | 13 GB | 6 bytes per hash    |

## Design

### Concurrency Model

The downloader divides the 1,048,576 prefixes evenly among N worker tasks. Each worker:

1. Fetches a prefix range from `api.pwnedpasswords.com/range/{PREFIX}`
2. Parses the response and converts each line to a 6-byte record
3. Writes the sorted binary file to disk
4. Updates the shared progress counter

Workers share a connection pool sized to match the worker count, maximizing HTTP connection reuse.

### Retry Logic

Failed requests are retried up to 10 times with exponential backoff starting at 100ms. This handles transient network issues and API rate limiting gracefully.

### Zero-Allocation Conversion

The hot path for converting API responses to binary avoids heap allocations:

- Prefix-to-hex conversion uses a stack-allocated 5-byte array
- Line-to-sha1t48 conversion writes directly to a 6-byte output buffer
- Hex-to-nibble conversion is a simple match expression

## Performance

Download speed depends primarily on network bandwidth and API rate limits.
With 64 concurrent workers on a fast connection, expect:

- ~1,000-2,000 prefixes per second
- Full download in 10-20 minutes

The conversion overhead is negligible compared to network latency.

## Related Projects

- [hibp-verifier](https://crates.io/crates/hibp-verifier) - The companion library for checking passwords against this dataset
- [oschonrock/hibp](https://github.com/oschonrock/hibp) - C++ implementation that inspired the sha1t64 format
- [HIBP Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) - The upstream data source

## License

MIT
