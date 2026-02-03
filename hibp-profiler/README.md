# hibp-profiler

Internal profiling tool for measuring hibp-verifier performance at the CPU cycle level.

## Purpose

This binary profiles the individual steps of password breach checking to identify where time is spent. It uses [rdtsc-timer](https://github.com/PrismaPhonic/rdtsc-timer) for precise cycle counting and breaks down each operation:

1. SHA1 hashing
2. Prefix extraction
3. File path construction and file open
4. File read
5. Search key extraction
6. Binary search

## Usage

Requires the HIBP dataset. Set `HIBP_DATA_DIR` to point to your dataset location:

```sh
HIBP_DATA_DIR=/path/to/hibp-data cargo run -p hibp-profiler --release
```

## Note

This crate is not published to crates.io. It exists for local development and performance analysis only.
