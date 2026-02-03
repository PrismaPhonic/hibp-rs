//! Breached password checker using the Have I Been Pwned dataset.
//!
//! This library provides zero-allocation password breach checking by reading
//! the HIBP dataset files and performing binary search on the sorted sha1t48 hashes.
//!
//! The binary format uses truncated 48-bit SHA1 hashes (6 bytes per record) stored
//! in sorted order, enabling efficient O(log n) binary search with direct indexing.
//!
//! # Async Support
//!
//! Enable the `tokio` feature for async support. This provides `is_breached_async()`
//! which uses `spawn_blocking` for file I/O, allowing use from async contexts without
//! blocking the runtime.
//!
//! Optionally you can use the `compio` feature instead to use the `compio`
//! runtime, which uses a non-work stealing model along with io-uring (io-uring
//! requires buffers stay thread local, so it doesn't pair well with tokio's
//! work stealing model)

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

        Ok(buf[..total].as_chunks::<RECORD_SIZE>().0.binary_search(&search_key).is_ok())
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
    fn build_path(&self, prefix_hex: [u8; PREFIX_LEN]) -> ([u8; 512], usize) {
        let base = self.dataset_path.as_os_str().as_encoded_bytes();
        let mut path_buf = [0u8; 512];
        let path_len = base.len() + 1 + PREFIX_LEN + 4; // +4 for ".bin"
        path_buf[..base.len()].copy_from_slice(base);
        path_buf[base.len()] = b'/';
        path_buf[base.len() + 1..base.len() + 1 + PREFIX_LEN].copy_from_slice(&prefix_hex);
        path_buf[base.len() + 1 + PREFIX_LEN..path_len].copy_from_slice(b".bin");

        (path_buf, path_len)
    }

    // Build file path without allocation: base_path + '/' + prefix + ".bin"
    #[inline(always)]
    fn open_file(&self, prefix_hex: [u8; PREFIX_LEN]) -> io::Result<File> {
        let (path_buf, path_len) = self.build_path(prefix_hex);

        // SAFETY: path_buf contains valid UTF-8 (base path + '/' + hex prefix + ".bin")
        let file_path = unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) };

        File::open(file_path)
    }

    /// Async version of `is_breached` using tokio.
    ///
    /// Performs SHA1 hashing and path construction on the async thread,
    /// then uses `spawn_blocking` only for file I/O.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hibp_verifier::BreachChecker;
    /// use std::path::Path;
    ///
    /// #[tokio::main]
    /// async fn main() -> std::io::Result<()> {
    ///     let checker = BreachChecker::new(Path::new("/path/to/hibp-data"));
    ///
    ///     if checker.is_breached_async("password123").await? {
    ///         println!("Password found in breach database!");
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "tokio")]
    pub async fn is_breached_async(&self, password: &str) -> io::Result<bool> {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash: [u8; 20] = hasher.finalize().into();

        let search_key: [u8; 6] = unsafe { hash[2..8].try_into().unwrap_unchecked() };

        let prefix_hex = Self::prefix_hex(&hash);
        let (path_buf, path_len) = self.build_path(prefix_hex);

        // Only file I/O goes into spawn_blocking
        tokio::task::spawn_blocking(move || {
            let file_path = unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) };
            let mut file = File::open(file_path)?;

            let mut buf = [0u8; 16384];
            let mut total = 0usize;
            loop {
                match file.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            Ok(buf[..total].as_chunks::<RECORD_SIZE>().0.binary_search(&search_key).is_ok())
        })
        .await
        .expect("spawn_blocking task panicked")
    }

    /// Async version of `is_breached` using compio's native io-uring file I/O.
    ///
    /// This method uses compio-fs which provides true async file operations
    /// via io-uring on Linux.
    ///
    /// compio is compatible with ntex's compio runtime feature, making this
    /// suitable for use within ntex web applications that want to use compio.
    #[cfg(feature = "compio")]
    pub async fn is_breached_compio(&self, password: &str) -> io::Result<bool> {
        use compio::fs::File;
        use compio::io::AsyncReadAt;

        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash: [u8; 20] = hasher.finalize().into();

        let search_key: [u8; 6] = unsafe { hash[2..8].try_into().unwrap_unchecked() };

        let prefix_hex = Self::prefix_hex(&hash);
        let (path_buf, path_len) = self.build_path(prefix_hex);
        let file_path = unsafe { std::str::from_utf8_unchecked(&path_buf[..path_len]) };

        let file = File::open(file_path).await?;

        // compio returns the buffer back to us after each operation
        let mut buf = [0u8; 16384];
        let mut total = 0usize;

        loop {
            let buf_result = file.read_at(buf, total as u64).await;
            buf = buf_result.1;
            match buf_result.0 {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(buf[..total].as_chunks::<RECORD_SIZE>().0.binary_search(&search_key).is_ok())
    }
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
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
                .is_ok()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x05])
                .is_ok()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x10])
                .is_ok()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                .is_ok()
        );

        // Test not finding non-existent records
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .is_err()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02])
                .is_err()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF])
                .is_err()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .is_err()
        );
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
                .is_err()
        );
    }

    #[test]
    fn test_single_record() {
        let data: Vec<u8> = vec![0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
                .is_ok()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .is_err()
        );
        assert!(
            data.as_chunks::<RECORD_SIZE>()
                .0
                .binary_search(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                .is_err()
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tokio_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires HIBP dataset"]
    async fn test_async_breached_password() {
        let path = dataset_path_from_env();
        let checker = BreachChecker::new(&path);

        let result = checker.is_breached_async("password123").await.unwrap();
        assert!(result, "password123 should be found in breach database");
    }

    #[tokio::test]
    #[ignore = "requires HIBP dataset"]
    async fn test_async_non_breached_password() {
        let path = dataset_path_from_env();
        let checker = BreachChecker::new(&path);

        let result = checker.is_breached_async("hAwT?}cuC:r#kW5").await.unwrap();
        assert!(!result, "random password should not be in breach database");
    }

    #[tokio::test]
    #[ignore = "requires HIBP dataset"]
    async fn test_async_matches_sync() {
        let path = dataset_path_from_env();
        let checker = BreachChecker::new(&path);

        let passwords = [
            "password123",
            "123456",
            "qwerty",
            "hAwT?}cuC:r#kW5",
            "letmein",
            "xK9#mP2$vL7@nQ4",
        ];

        for password in passwords {
            let sync_result = checker.is_breached(password).unwrap();
            let async_result = checker.is_breached_async(password).await.unwrap();
            assert_eq!(
                sync_result, async_result,
                "sync and async results should match for '{}'",
                password
            );
        }
    }
}

#[cfg(all(test, feature = "compio"))]
mod compio_tests {
    use compio::runtime as compio_runtime;

    use super::*;

    #[test]
    #[ignore = "requires HIBP dataset"]
    fn test_compio_breached_password() {
        let path = dataset_path_from_env();

        compio_runtime::Runtime::new().unwrap().block_on(async {
            let checker = BreachChecker::new(&path);
            let result = checker.is_breached_compio("password123").await.unwrap();
            assert!(result, "password123 should be found in breach database");
        });
    }

    #[test]
    #[ignore = "requires HIBP dataset"]
    fn test_compio_non_breached_password() {
        let path = dataset_path_from_env();

        compio_runtime::Runtime::new().unwrap().block_on(async {
            let checker = BreachChecker::new(&path);
            let result = checker.is_breached_compio("hAwT?}cuC:r#kW5").await.unwrap();
            assert!(!result, "random password should not be in breach database");
        });
    }

    #[test]
    #[ignore = "requires HIBP dataset"]
    fn test_compio_matches_sync() {
        let path = dataset_path_from_env();

        compio_runtime::Runtime::new().unwrap().block_on(async {
            let checker = BreachChecker::new(&path);

            let passwords = [
                "password123",
                "123456",
                "qwerty",
                "hAwT?}cuC:r#kW5",
                "letmein",
                "xK9#mP2$vL7@nQ4",
            ];

            for password in passwords {
                let sync_result = checker.is_breached(password).unwrap();
                let compio_result = checker.is_breached_compio(password).await.unwrap();
                assert_eq!(
                    sync_result, compio_result,
                    "sync and compio results should match for '{}'",
                    password
                );
            }
        });
    }
}
