//! Profiling binary for breached-password-searcher
//!
//! This binary profiles the individual steps of password breach checking
//! to identify where time is spent. Uses the same zero-allocation techniques
//! as the library.

use std::fs::File;
use std::path::Path;

use hibp_verifier::{
    BreachChecker, HEX_CHARS, PREFIX_LEN, binary_search_sha1t48, dataset_path_from_env,
};
use memmap2::Mmap;
use rdtsc_timer::{Profiler, time};
use sha1::{Digest, Sha1};

/// Profile a single password check, broken down by step
/// Uses the same zero-allocation path building as the library
fn profile_password_check<const N: usize>(
    mut profiler: &mut Profiler<N>,
    password: &str,
    dataset_path: &Path,
) -> bool {
    // Step 1: SHA1 hash
    let hash: [u8; 20] = time!(profiler, "sha1_hash", {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher.finalize().into()
    });

    // Step 2: Extract prefix hex (zero-allocation)
    let prefix_hex: [u8; PREFIX_LEN] = time!(profiler, "extract_prefix", {
        [
            HEX_CHARS[(hash[0] >> 4) as usize],
            HEX_CHARS[(hash[0] & 0x0f) as usize],
            HEX_CHARS[(hash[1] >> 4) as usize],
            HEX_CHARS[(hash[1] & 0x0f) as usize],
            HEX_CHARS[(hash[2] >> 4) as usize],
        ]
    });

    // Step 3: Build file path (zero-allocation, matching library implementation)
    let base = dataset_path.as_os_str().as_encoded_bytes();
    let mut path_buf = [0u8; 512];
    let path_len = base.len() + 1 + PREFIX_LEN + 4; // +4 for ".bin"
    let file_path: &str = time!(profiler, "build_path", {
        path_buf[..base.len()].copy_from_slice(base);
        path_buf[base.len()] = b'/';
        path_buf[base.len() + 1..base.len() + 1 + PREFIX_LEN].copy_from_slice(&prefix_hex);
        path_buf[base.len() + 1 + PREFIX_LEN..path_len].copy_from_slice(b".bin");
        unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) }
    });

    // Step 4: Open file
    let file: File = time!(profiler, "file_open", {
        File::open(file_path).expect("Failed to open file")
    });

    // Step 5: Memory map
    let mmap: Mmap = time!(profiler, "mmap", {
        unsafe { Mmap::map(&file).expect("Failed to mmap") }
    });

    // Step 6: Extract search key
    let search_key: [u8; 6] = time!(profiler, "extract_search_key", {
        hash[2..8].try_into().unwrap()
    });

    // Step 7: Binary search
    let found: bool = time!(profiler, "binary_search", {
        binary_search_sha1t48(&mmap, &search_key)
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
        let mut profiler: Profiler<7> =
            Profiler::new("Breached password (password123) - POSITIVE PATH");
        let found = profile_password_check(&mut profiler, "password123", dataset_path);
        assert!(found, "password123 should be found");
        profiler.finalize();
    }

    // Profile a non-breached password (negative case)
    // "hAwT?}cuC:r#kW5" -> not in database
    {
        let mut profiler: Profiler<7> =
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
