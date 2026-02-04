//! Profiling binary for breached-password-searcher
//!
//! This binary profiles the individual steps of password breach checking
//! to identify where time is spent. Uses the same zero-allocation techniques
//! as the library.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use hibp_verifier::{BreachChecker, PREFIX_LEN, RECORD_SIZE, dataset_path_from_env};
use rdtsc_timer::{Profiler, time};
use sha1::{Digest, Sha1};

/// Profile a single password check, broken down by step
/// Uses the same zero-allocation path building as the library
fn profile_password_check<const N: usize>(
    mut profiler: &mut Profiler<N>,
    password: &str,
    dataset_path: &Path,
) -> bool {
    let checker = BreachChecker::new(dataset_path);

    // Step 1: SHA1 hash
    let hash: [u8; 20] = time!(profiler, "sha1_hash", {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher.finalize().into()
    });

    // Step 2: Extract prefix hex
    let prefix_hex: [u8; PREFIX_LEN] = time!(profiler, "extract_prefix", {
        BreachChecker::prefix_hex(&hash)
    });

    // Step 3: Build file path and open file.
    let mut file: File = time!(profiler, "build_path and file_open", {
        checker.open_file(prefix_hex).expect("Failed to open file")
    });

    // Step 4: Read from file.
    let (buf, n) = time!(profiler, "file_read", {
        let mut buf = [0u8; 16384];
        let n = file.read(&mut buf).unwrap();
        (buf, n)
    });

    // Step 5: Extract search key
    let search_key: [u8; 6] = time!(profiler, "extract_search_key", {
        unsafe { hash[2..8].try_into().unwrap_unchecked() }
    });

    // Step 6: Binary search
    let found: bool = time!(profiler, "binary_search", {
        buf[..n].as_chunks::<RECORD_SIZE>().0.binary_search(&search_key).is_ok()
    });

    found
}

fn main() {
    println!("=== Breached Password Searcher Profiling ===\n");

    let dataset_path = dataset_path_from_env();

    if !dataset_path.exists() {
        eprintln!("Dataset not found at: {:?}", dataset_path);
        eprintln!("Set HIBP_DATA_DIR or run the downloader first.");
        std::process::exit(1);
    }

    let dataset_path = dataset_path.as_path();

    // Profile a known breached password (positive case)
    // "password123" -> SHA1: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
    {
        let mut profiler: Profiler<6> =
            Profiler::new("Breached password (password123) - POSITIVE PATH");
        let found = profile_password_check(&mut profiler, "password123", dataset_path);
        assert!(found, "password123 should be found");
        profiler.finalize();
    }

    // Profile a non-breached password (negative case)
    // "hAwT?}cuC:r#kW5" -> not in database
    {
        let mut profiler: Profiler<6> =
            Profiler::new("Non-breached password (hAwT?}cuC:r#kW5) - NEGATIVE PATH");
        let found = profile_password_check(&mut profiler, "hAwT?}cuC:r#kW5", dataset_path);
        assert!(!found, "random password should not be found");
        profiler.finalize();
    }

    // Aggregated timing using the actual library code paths
    let iterations = 1000;
    println!(
        "\n=== Averaging over {} iterations (using library code) ===\n",
        iterations
    );

    let checker = BreachChecker::new(dataset_path);

    let start = rdtsc_timer::cpu_timer();
    for _ in 0..iterations {
        let _ = checker.is_breached("password123");
    }
    let end = rdtsc_timer::cpu_timer();
    let cycles_per_iter = (end - start) / iterations as u64;
    println!(
        "Breached password (password123): {} cycles/iter average",
        cycles_per_iter
    );

    let start = rdtsc_timer::cpu_timer();
    for _ in 0..iterations {
        let _ = checker.is_breached("hAwT?}cuC:r#kW5");
    }
    let end = rdtsc_timer::cpu_timer();
    let cycles_per_iter = (end - start) / iterations as u64;
    println!(
        "Non-breached password (hAwT?}}cuC:r#kW5): {} cycles/iter average",
        cycles_per_iter
    );
}
