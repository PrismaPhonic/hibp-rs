# hibp-downloader

[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/hibp-rs/ci.yml?branch=main)](https://github.com/PrismaPhonic/hibp-rs/actions)
[![crates.io](https://img.shields.io/crates/v/hibp-downloader.svg)](https://crates.io/crates/hibp-downloader)
[![docs.rs](https://docs.rs/hibp-downloader/badge.svg)](https://docs.rs/hibp-downloader)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/hibp-rs)

A fast, concurrent downloader for the Have I Been Pwned password hash database.
Converts the HIBP API responses directly into a compact binary format using
truncated 48-bit SHA1 hashes (sha1t48).

## Features

- Concurrent downloads with configurable worker count
- Direct conversion to compact binary format (no intermediate files)
- Resume support for interrupted downloads
- Progress bar with ETA
- Exponential backoff retry logic for transient failures

## Installation

```sh
cargo install hibp-downloader
```

## Usage

Download the full dataset:

```sh
hibp-downloader --output ./hibp-data
```

With more concurrent workers (default is 64):

```sh
hibp-downloader --output ./hibp-data --concurrent-workers 128
```

Resume an interrupted download:

```sh
hibp-downloader --output ./hibp-data --resume
```

Force overwrite existing data:

```sh
hibp-downloader --output ./hibp-data --force
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output directory for binary files (required) |
| `-j, --concurrent-workers` | Number of concurrent download workers (default: 64) |
| `--resume` | Skip existing files and continue downloading |
| `--force` | Remove existing output directory before starting |
| `--limit` | Maximum prefix index to download (for testing) |
| `--no-progress` | Disable progress bar |

## Binary Format

The downloader produces 1,048,576 files (one per 5-character hex prefix), each
containing sorted 6-byte records. This format is based on the sha1t64 approach
from [oschonrock/hibp](https://github.com/oschonrock/hibp) but we only store the 6 byte suffix. The first 2 bytes are redundant, as the file names themselves contain a 2.5 byte prefix.

### Why sha1t48?

The HIBP dataset contains approximately 900 million SHA1 password hashes. Storing
the full 20-byte hash for each entry requires significant space. By truncating to
48 bits, we reduce storage by over 4x while maintaining an acceptably low
collision probability.

With ~900 million entries, the probability of at least one collision is
approximately 1 in 10 billion. For password breach checking, a false positive
(incorrectly marking a password as breached) is harmless in practice.

### File Layout

Each prefix file (e.g., `00000.bin`, `FFFFF.bin`) contains:

- Fixed 6-byte records (suffix, avoiding redundant 2 byte prefix)
- Sorted in ascending order
- Direct indexing: record N is at byte offset N * 6

This enables O(log n) binary search with no parsing overhead.

### Storage Comparison

| Format | Size | Notes |
|--------|------|-------|
| HIBP Text (original) | 77 GB | SHA1:count per line |
| sha1t48 binary | 13 GB | 6 bytes per hash |

## Design

### Concurrency Model

The downloader divides the 1,048,576 prefixes evenly among N worker tasks. Each worker:

1. Fetches a prefix range from `api.pwnedpasswords.com/range/{PREFIX}`
2. Parses the response and converts each line to sha1t48
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

- [oschonrock/hibp](https://github.com/oschonrock/hibp) - C++ implementation that inspired the sha1t64 format
- [HIBP Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) - The upstream data source

## License

MIT
