# hibp-verifier

[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/hibp-rs/ci.yml?branch=main)](https://github.com/PrismaPhonic/hibp-rs/actions)
[![crates.io](https://img.shields.io/crates/v/hibp-verifier.svg)](https://crates.io/crates/hibp-verifier)
[![docs.rs](https://docs.rs/hibp-verifier/badge.svg)](https://docs.rs/hibp-verifier)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/hibp-rs)

A high-performance library for checking passwords against the Have I Been Pwned
breach database. Uses stack buffer file reads and binary search for
sub-microsecond lookups.

## Features

- Zero-allocation hot path for password checking (sync API)
- O(log n) binary search on sorted sha1t48 records
- ~0.9 microseconds per lookup on warm cache
- Optional async API with tokio or compio support

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hibp-verifier = "0.1"
```

## Usage

```rust
use hibp_verifier::BreachChecker;
use std::path::Path;

let checker = BreachChecker::new(Path::new("/path/to/hibp-data"));

match checker.is_breached("password123") {
    Ok(true) => println!("Password found in breach database"),
    Ok(false) => println!("Password not found"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Async Usage

Enable the `tokio` feature for async support:

```toml
[dependencies]
hibp-verifier = { version = "0.1", features = ["tokio"] }
```

The async API performs SHA1 hashing and path construction on the async thread,
then uses `spawn_blocking` only for file I/O. This is faster than
`tokio::fs::File` because it uses a single blocking call instead of multiple
calls per I/O operation.

### Example

```rust
use hibp_verifier::BreachChecker;
use std::path::Path;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let checker = BreachChecker::new(Path::new("/path/to/hibp-data"));

    if checker.is_breached_async("password123").await? {
        println!("Password found in breach database!");
    }

    Ok(())
}
```

## Compio Usage (io-uring)

Enable the `compio` feature for native io-uring async support:

```toml
[dependencies]
hibp-verifier = { version = "0.1", features = ["compio"] }
```

This uses compio's native io-uring file I/O with a multi-threaded dispatcher.
Note that benchmarks show this is ~1.5x slower than the tokio `spawn_blocking`
approach. See the Performance section for details.

### Example

```rust
use hibp_verifier::BreachChecker;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let checker = BreachChecker::new(Path::new("/path/to/hibp-data"));

    compio::runtime::Runtime::new()?.block_on(async {
        if checker.is_breached_compio("password123").await? {
            println!("Password found in breach database!");
        }
        Ok(())
    })
}
```

## Dataset Setup

The verifier requires a pre-downloaded dataset in sha1t48 binary format. Use
[hibp-downloader](https://crates.io/crates/hibp-downloader) to fetch and convert the data:

```sh
cargo install hibp-downloader
hibp-downloader --output /path/to/hibp-data
```

### Specifying the Dataset Location

Set the `HIBP_DATA_DIR` environment variable to point to your dataset:

```sh
export HIBP_DATA_DIR=/path/to/hibp-data
```

If unset, tests and benchmarks fall back to `pwnedpasswords-bin` in the
workspace root (sibling to the `hibp-verifier` directory).

### Running Tests

Unit tests that do not require the dataset run by default:

```sh
cargo test -p hibp-verifier
```

To run tests that require the dataset, use the `--ignored` flag:

```sh
HIBP_DATA_DIR=/path/to/hibp-data cargo test -p hibp-verifier -- --ignored
```

To run all tests (both regular and ignored):

```sh
HIBP_DATA_DIR=/path/to/hibp-data cargo test -p hibp-verifier -- --include-ignored
```

### Running Benchmarks

Sync benchmarks:

```sh
HIBP_DATA_DIR=/path/to/hibp-data cargo bench -p hibp-verifier
```

Async benchmarks:

```sh
HIBP_DATA_DIR=/path/to/hibp-data cargo bench -p hibp-verifier --features tokio
```

## Binary Format

The library expects a directory containing 1,048,576 files named `00000.bin`
through `FFFFF.bin`. Each file contains sorted 6-byte sha1t48 records for the
corresponding SHA1 prefix (skipping first 2 bytes, as it's redundantly in the
2.5 byte prefix of the file name).

### Record Layout

Each record is bytes 2 to 8 of a SHA1 hash (truncated to 48 bits). Records are
stored in ascending sorted order, enabling binary search.

### Collision Probability

With ~900 million entries, the probability of a false positive (collision) is
approximately 1 in 10 billion. For breach checking, false positives are harmless
since they only cause rejection of a password that could reasonably be avoided.

## Performance

### Sync API (Zero-Allocation)

Benchmark results on a modern CPU with data in page cache:

| Benchmark | Time per batch | Time per password |
|-----------|----------------|-------------------|
| common_passwords_20 | ~27.9 µs | ~1.39 µs |
| random_passwords_20 | ~28.2 µs | ~1.41 µs |
| mixed_passwords_40 | ~55.3 µs | ~1.38 µs |

The bottleneck is `File::open` and file read overhead. The actual binary
search completes in nanoseconds.

### Async API

High concurrency comparison (10k concurrent lookups, 24 worker threads):

| Method | Time | Per password | Notes |
|--------|------|--------------|-------|
| `is_breached_async` | ~31 ms | ~3.1 µs | **Winner** - tokio thread pool |
| `is_breached_compio` | ~46 ms | ~4.6 µs | 1.5x slower - compio |
| tokio::fs | ~57 ms | ~5.7 µs | 1.8x slower - not exposed |
| std::thread::scope | ~198 ms | ~19.8 µs | OS thread creation overhead |

#### Method Explanations

##### `is_breached_async` (Recommended)

Uses `tokio::task::spawn_blocking` to run the entire sync file I/O operation on
tokio's blocking thread pool. The pool is warmed and reused across calls,
avoiding thread creation overhead. This approach wins because:

1. Thread pool threads are pre-spawned and reused
2. Work-stealing distributes load across all pool threads
3. Single syscall batch (open + read + close) per operation

##### `is_breached_compio` (io-uring)

Uses compio's native io-uring file I/O with a multi-threaded dispatcher.
Despite io-uring being a more efficient kernel interface, this approach is
~1.5x slower than spawn_blocking. The compio dispatcher distributes tasks
across worker threads, but lacks tokio's work-stealing scheduler which more efficiently balances load. The irony here is that io-uring *must* be used with a non work stealing model, because the buffers must stay thread local. This does perform much better than tokio does with io-uring, but still strictly worse than spawn_blocking.

##### tokio::fs (benchmarked but not exposed)

Uses `tokio::fs::File` for "native" async file access. This is **not exposed** in the library API because it performs worse than `is_breached_async`. It's
included in benchmarks only to demonstrate why.

Tokio's async filesystem API internally wraps *every individual operation* in a separate `spawn_blocking` call:

- `File::open()` → spawn_blocking
- `file.read()` → spawn_blocking (per call)

The overhead of multiple spawn_blocking round-trips makes this slower than
doing a single spawn_blocking for the entire operation.

#### Why spawn_blocking Wins

The key insight is that `spawn_blocking` distributes work across tokio's
blocking thread pool (default: 512 threads). Each file I/O operation runs in
parallel on a real OS thread, but thread creation/destruction overhead is
amortized because:

1. **Thread reuse**: Pool threads persist and handle many operations
2. **Work stealing**: Idle threads pull work from busy threads' queues
3. **Bounded concurrency**: The pool size prevents thread explosion

In contrast, `std::thread::scope` creates 10k OS threads simultaneously,
overwhelming the scheduler with context switches and memory allocation for
thread stacks.

## Design

### Zero-Allocation Path Building

The library constructs file paths without heap allocation by writing directly
into a 512-byte stack buffer:

```rust
let mut path_buf = [0u8; 512];
// ... copy base path, separator, prefix hex, and ".bin" suffix
```

### Binary Search

Each prefix file is read into a stack allocated buffer.
Binary search uses direct indexing since records are fixed-size:

```rust
let offset = mid * RECORD_SIZE;  // RECORD_SIZE = 6
let record = &data[offset..offset + RECORD_SIZE];
```

## License

MIT
