//! Breached password checker using the Have I Been Pwned dataset.
//!
//! This library provides zero-allocation password breach checking by memory-mapping
//! the HIBP dataset files and performing binary search on the sorted sha1t64 hashes.
//!
//! The binary format uses truncated 64-bit SHA1 hashes (8 bytes per record) stored
//! in sorted order, enabling efficient O(log n) binary search with direct indexing.

use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

/// Environment variable name for specifying the HIBP dataset directory.
pub const HIBP_DATA_DIR_ENV: &str = "HIBP_DATA_DIR";

/// Returns the dataset path from the HIBP_DATA_DIR environment variable,
/// or falls back to the default location (pwnedpasswords-bin sibling directory).
pub fn dataset_path_from_env() -> PathBuf {
    std::env::var(HIBP_DATA_DIR_ENV).map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("pwndpasswords-bin")
    })
}

/// The length of a sha1t64 record in bytes (truncated 64-bit hash).
pub const RECORD_SIZE: usize = 6;

/// The length of a SHA1 hash prefix used for file naming (5 hex characters).
pub const PREFIX_LEN: usize = 5;

/// Hex lookup table for prefix conversion.
pub const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

/// Checks if a password has been found in known data breaches.
///
/// This struct holds a reference to the directory containing the HIBP binary dataset files.
pub struct BreachChecker<'a> {
    dataset_path: &'a Path,
}

impl<'a> BreachChecker<'a> {
    /// Creates a new BreachChecker with the given dataset directory path.
    ///
    /// The directory should contain binary files named `{PREFIX}.bin` where PREFIX
    /// is a 5-character uppercase hex string (00000-FFFFF).
    pub fn new(dataset_path: &'a Path) -> Self {
        Self { dataset_path }
    }

    /// Checks if the given password has been found in a data breach.
    ///
    /// Returns `Ok(true)` if the password was found in the breach database,
    /// `Ok(false)` if it was not found, or an error if the lookup failed.
    pub fn is_breached(&self, password: &str) -> io::Result<bool> {
        // Compute SHA1 hash as raw bytes
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash: [u8; 20] = hasher.finalize().into();

        let prefix_hex = Self::prefix_hex(&hash);
        let mut file = self.open_file(prefix_hex)?;

        // largest file size currently is 14.6KB for 6-byte records (2495 records in that prefix
        // file) Use a 16KB stack buffer to avoid allocation. This should provide room for
        // growth over time.
        let mut buf = [0u8; 16384];

        // read() is not guaranteed to return the full file in a single call.
        // This loop logic handles ensuring we always read to the end.
        //
        // I've benchmarked this against getting the metadata for the file
        // upfront and reading until total bytes read == size from metadata, and
        // that approach was slower. Likely because fstat() has to copy the full
        // stat structure(144 bytes on x86_64) from kernel to userspace.
        let mut total = 0usize;
        loop {
            match file.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        let search_key: [u8; 6] = unsafe { hash[2..8].try_into().unwrap_unchecked() };

        Ok(binary_search_sha1t48(&buf[..total], &search_key))
    }

    /// Returns the prefix for the hash as hex (first 5 hex chars == first 2.5 bytes)
    /// that matches the file name on disk where the hash might be found.
    #[inline(always)]
    fn prefix_hex(hash: &[u8; 20]) -> [u8; PREFIX_LEN] {
        let mut prefix_hex = [0u8; PREFIX_LEN];

        prefix_hex[0] = HEX_CHARS[(hash[0] >> 4) as usize];
        prefix_hex[1] = HEX_CHARS[(hash[0] & 0x0f) as usize];
        prefix_hex[2] = HEX_CHARS[(hash[1] >> 4) as usize];
        prefix_hex[3] = HEX_CHARS[(hash[1] & 0x0f) as usize];
        prefix_hex[4] = HEX_CHARS[(hash[2] >> 4) as usize];

        prefix_hex
    }

    // Build file path without allocation: base_path + '/' + prefix + ".bin"
    #[inline(always)]
    fn open_file(&self, prefix_hex: [u8; PREFIX_LEN]) -> io::Result<File> {
        let base = self.dataset_path.as_os_str().as_encoded_bytes();
        let mut path_buf = [0u8; 512];
        let path_len = base.len() + 1 + PREFIX_LEN + 4; // +4 for ".bin"
        path_buf[..base.len()].copy_from_slice(base);
        path_buf[base.len()] = b'/';
        path_buf[base.len() + 1..base.len() + 1 + PREFIX_LEN].copy_from_slice(&prefix_hex);
        path_buf[base.len() + 1 + PREFIX_LEN..path_len].copy_from_slice(b".bin");

        // SAFETY: path_buf contains valid UTF-8 (base path + '/' + hex prefix + ".bin")
        let file_path = unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) };

        File::open(file_path)
    }
}

/// Binary searches for a sha1t48 hash in a memory-mapped binary file.
///
/// The file contains fixed-size 6-byte records in sorted order, enabling
/// direct index calculation.
#[inline(always)]
pub fn binary_search_sha1t48(data: &[u8], search_key: &[u8; 6]) -> bool {
    if data.is_empty() {
        return false;
    }

    let record_count = data.len() / RECORD_SIZE;
    let mut low = 0usize;
    let mut high = record_count;

    while low < high {
        let mid = low + (high - low) / 2;
        let offset = mid * RECORD_SIZE;

        let record = &data[offset..offset + RECORD_SIZE];

        match record.cmp(search_key) {
            Ordering::Equal => return true,
            Ordering::Less => low = mid + 1,
            Ordering::Greater => high = mid,
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1t64_conversion() {
        // password123 -> SHA1: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
        // sha1t64 (first 8 bytes): CB FD AC 60 08 F9 CA B4
        let mut hasher = Sha1::new();
        hasher.update(b"password123");
        let hash: [u8; 20] = hasher.finalize().into();

        assert_eq!(hash[0], 0xCB);
        assert_eq!(hash[1], 0xFD);
        assert_eq!(hash[2], 0xAC);
        assert_eq!(hash[3], 0x60);
        assert_eq!(hash[4], 0x08);
        assert_eq!(hash[5], 0xF9);
        assert_eq!(hash[6], 0xCA);
        assert_eq!(hash[7], 0xB4);
    }

    #[test]
    #[ignore = "requires HIBP dataset"]
    fn test_breached_password() {
        // "password123" is a commonly breached password
        // SHA1: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
        // Prefix: CBFDA
        let path = dataset_path_from_env();
        let checker = BreachChecker::new(&path);
        let result = checker.is_breached("password123").unwrap();
        assert!(result, "password123 should be found in the breach database");
    }

    #[test]
    #[ignore = "requires HIBP dataset"]
    fn test_non_breached_password() {
        let path = dataset_path_from_env();
        let checker = BreachChecker::new(&path);
        // "hAwT?}cuC:r#kW5" is a complex random password that shouldn't be in breaches
        let result = checker.is_breached("hAwT?}cuC:r#kW5").unwrap();
        assert!(
            !result,
            "random complex password should not be in the breach database"
        );
    }

    #[test]
    fn test_binary_search_sha1t48() {
        // Create a small sorted dataset for testing
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // record 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // record 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // record 2
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // record 3
        ];

        // Test finding existing records
        assert!(binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        ));
        assert!(binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05]
        ));
        assert!(binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x10]
        ));
        assert!(binary_search_sha1t48(
            &data,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        ));

        // Test not finding non-existent records
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ));
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        ));
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]
        ));
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ));
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        ));
    }

    #[test]
    fn test_single_record() {
        let data: Vec<u8> = vec![0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        assert!(binary_search_sha1t48(
            &data,
            &[0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        ));
        assert!(!binary_search_sha1t48(
            &data,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ));
        assert!(!binary_search_sha1t48(
            &data,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        ));
    }
}
