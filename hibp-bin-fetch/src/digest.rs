use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::fs;

use crate::conversion::prefix_to_hex;

static SHA_FILE_SUFFIX: &[u8; 7] = b".sha256";

/// Compute the SHA-256 digest of the given bytes.
pub fn compute(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Takes in a base directory and prefix, and returns a pathbuf to the prefixes
/// sha256 filepath.
pub fn prefix_to_sha_filepath(dir: &Path, prefix: u32) -> PathBuf {
    // prefix (5 hex bytes) + .sha256 (7 bytes)  = 12
    let mut buf = [0u8; 12];
    buf[..5].copy_from_slice(&prefix_to_hex(prefix));
    buf[5..].copy_from_slice(SHA_FILE_SUFFIX);
    // SAFETY: Garaunteed to be valid utf8 bytes.
    let filename = unsafe { std::str::from_utf8(&buf).unwrap_unchecked() };
    dir.join(filename)
}

/// Read the stored SHA-256 digest for a prefix from the digests directory.
/// Returns None if the file does not exist or is corrupt.
pub async fn read(dir: &Path, prefix: u32) -> io::Result<Option<[u8; 32]>> {
    let path = prefix_to_sha_filepath(dir, prefix);
    match fs::read(&path).await {
        Ok(bytes) if bytes.len() == 32 => Ok(Some(bytes.try_into().unwrap())),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write a SHA-256 digest for a prefix to the digests directory.
pub async fn write(dir: &Path, prefix: u32, digest: &[u8; 32]) -> io::Result<()> {
    let path = prefix_to_sha_filepath(dir, prefix);
    fs::write(&path, digest).await
}
