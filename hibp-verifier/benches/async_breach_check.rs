mod common;

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "tokio")]
fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(24)
        .enable_all()
        .build()
        .unwrap()
}

/// Breach check using tokio::fs directly.
///
/// This function is NOT exposed in the library API because it performs worse than
/// `is_breached_async` (which uses spawn_blocking). It's included here for benchmarking
/// purposes only to demonstrate why the spawn_blocking approach is preferred.
///
/// tokio::fs wraps every individual operation (open, read) in a separate spawn_blocking
/// call, which adds overhead compared to a single spawn_blocking for the entire operation.
#[cfg(feature = "tokio")]
async fn is_breached_tokio_fs(
    dataset_path: &std::path::Path,
    password: &str,
) -> std::io::Result<bool> {
    use hibp_verifier::{HEX_CHARS, PREFIX_LEN, RECORD_SIZE};
    use sha1::{Digest, Sha1};
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash: [u8; 20] = hasher.finalize().into();

    let mut prefix_hex = [0u8; PREFIX_LEN];
    prefix_hex[0] = HEX_CHARS[(hash[0] >> 4) as usize];
    prefix_hex[1] = HEX_CHARS[(hash[0] & 0x0f) as usize];
    prefix_hex[2] = HEX_CHARS[(hash[1] >> 4) as usize];
    prefix_hex[3] = HEX_CHARS[(hash[1] & 0x0f) as usize];
    prefix_hex[4] = HEX_CHARS[(hash[2] >> 4) as usize];

    let base = dataset_path.as_os_str().as_encoded_bytes();
    let mut path_buf = [0u8; 512];
    let path_len = base.len() + 1 + PREFIX_LEN + 4;
    path_buf[..base.len()].copy_from_slice(base);
    path_buf[base.len()] = b'/';
    path_buf[base.len() + 1..base.len() + 1 + PREFIX_LEN].copy_from_slice(&prefix_hex);
    path_buf[base.len() + 1 + PREFIX_LEN..path_len].copy_from_slice(b".bin");

    let file_path = unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) };

    // Open file using tokio::fs (internally uses spawn_blocking)
    let mut file = File::open(file_path).await?;

    // Read file contents (each read internally uses spawn_blocking)
    let mut buf = [0u8; 16384];
    let mut total = 0usize;
    loop {
        match file.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let search_key: [u8; 6] = unsafe { hash[2..8].try_into().unwrap_unchecked() };

    Ok(buf[..total].as_chunks::<RECORD_SIZE>().0.binary_search(&search_key).is_ok())
}

// Benchmark: Sync baseline with std::thread::scope (always runs, no features required)
fn bench_sync_concurrency(c: &mut Criterion) {
    use std::path::PathBuf;

    use common::generate_random_passwords;
    use criterion::{BatchSize, black_box};
    use hibp_verifier::{BreachChecker, dataset_path_from_env};

    let path = dataset_path_from_env();
    let passwords = generate_random_passwords(10000);

    let test_data: Vec<(PathBuf, String)> =
        passwords.into_iter().map(|password| (path.clone(), password)).collect();

    let mut group = c.benchmark_group("concurrent_10k");

    group.bench_function("sync_threads", |b| {
        b.iter_batched(
            || test_data.clone(),
            |data| {
                std::thread::scope(|s| {
                    let handles: Vec<_> = data
                        .iter()
                        .map(|(path, password)| {
                            s.spawn(|| {
                                let checker = BreachChecker::new(path);
                                checker.is_breached(password)
                            })
                        })
                        .collect();

                    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
                    black_box(results)
                })
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

// Benchmark: High concurrency comparison (10k concurrent lookups) - tokio
#[cfg(feature = "tokio")]
fn bench_tokio_concurrency(c: &mut Criterion) {
    use std::path::PathBuf;

    use common::generate_random_passwords;
    use criterion::{BatchSize, black_box};
    use futures::future::join_all;
    use hibp_verifier::{BreachChecker, dataset_path_from_env};

    let rt = make_runtime();
    let path = dataset_path_from_env();
    let passwords = generate_random_passwords(10000);

    let test_data: Vec<(PathBuf, String)> =
        passwords.into_iter().map(|password| (path.clone(), password)).collect();

    let mut group = c.benchmark_group("concurrent_10k");

    // Async API (is_breached_async - spawn_blocking)
    group.bench_function("is_breached_async", |b| {
        b.to_async(&rt).iter_batched(
            || test_data.clone(),
            |data| async move {
                let futs: Vec<_> = data
                    .into_iter()
                    .map(|(path, password)| async move {
                        let checker = BreachChecker::new(&path);
                        checker.is_breached_async(&password).await
                    })
                    .collect();

                let results: Vec<_> = join_all(futs).await;
                black_box(results)
            },
            BatchSize::LargeInput,
        );
    });

    // Async API (tokio::fs - NOT exposed in library, for benchmark comparison only)
    group.bench_function("is_breached_tokio_fs", |b| {
        b.to_async(&rt).iter_batched(
            || test_data.clone(),
            |data| async move {
                let futs: Vec<_> =
                    data.into_iter()
                        .map(|(path, password)| async move {
                            is_breached_tokio_fs(&path, &password).await
                        })
                        .collect();

                let results: Vec<_> = join_all(futs).await;
                black_box(results)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

#[cfg(not(feature = "tokio"))]
fn bench_tokio_concurrency(_c: &mut Criterion) {}

// Benchmark: High concurrency comparison (10k concurrent lookups) - compio
#[cfg(feature = "compio")]
fn bench_compio_concurrency(c: &mut Criterion) {
    use std::num::NonZeroUsize;
    use std::path::PathBuf;

    use common::generate_random_passwords;
    use compio::dispatcher::Dispatcher;
    use criterion::{BatchSize, black_box};
    use hibp_verifier::{BreachChecker, dataset_path_from_env};

    let dispatcher = Dispatcher::builder()
        .worker_threads(NonZeroUsize::new(24).unwrap())
        .build()
        .unwrap();

    let rt = compio::runtime::Runtime::new().unwrap();

    let path = dataset_path_from_env();
    let passwords = generate_random_passwords(10000);

    let test_data: Vec<(PathBuf, String)> =
        passwords.into_iter().map(|password| (path.clone(), password)).collect();

    let mut group = c.benchmark_group("concurrent_10k");

    group.bench_function("is_breached_compio", |b| {
        b.iter_batched(
            || test_data.clone(),
            |data| {
                let receivers: Vec<_> = data
                    .into_iter()
                    .map(|(path, password)| {
                        dispatcher
                            .dispatch(move || async move {
                                let checker = BreachChecker::new(&path);
                                checker.is_breached_compio(&password).await
                            })
                            .unwrap()
                    })
                    .collect();

                let results: Vec<_> = rt.block_on(async {
                    let mut results = Vec::with_capacity(receivers.len());
                    for rx in receivers {
                        results.push(rx.await.unwrap());
                    }
                    results
                });

                black_box(results)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

#[cfg(not(feature = "compio"))]
fn bench_compio_concurrency(_c: &mut Criterion) {}

criterion_group!(
    async_benches,
    bench_sync_concurrency,
    bench_tokio_concurrency,
    bench_compio_concurrency
);
criterion_main!(async_benches);
