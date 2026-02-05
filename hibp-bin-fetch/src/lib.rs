//! Downloads the Have I Been Pwned password hash database and converts it to a
//! compact 6-byte binary format for use with [hibp-verifier](https://crates.io/crates/hibp-verifier).
//!
//! **This is not a general-purpose HIBP downloader.** It produces a custom binary
//! format (sha1t48) specifically designed for fast password breach checking with
//! `hibp-verifier`. If you need the original HIBP data format, use the official
//! [Pwned Passwords downloader](https://haveibeenpwned.com/Passwords).
//!
//! # Binary Format
//!
//! This tool produces 1,048,576 binary files (one per 5-character hex prefix), each
//! containing sorted 6-byte records. The first 2.5 bytes of each SHA1 hash are encoded
//! in the filename, so we store only bytes 2-7 (the 6-byte suffix) in each record.
//!
//! Each prefix file (e.g., `00000.bin`, `FFFFF.bin`) contains:
//!
//! - Fixed 6-byte records (bytes 2-7 of the SHA1 hash)
//! - Sorted in ascending order
//! - Direct indexing: record N is at byte offset N * 6
//!
//! This enables O(log n) binary search with no parsing overhead, which is exactly
//! what `hibp-verifier` uses for sub-microsecond lookups.
//!
//! # Why This Format?
//!
//! The HIBP dataset contains approximately 900 million SHA1 password hashes. Storing
//! the full 20-byte hash for each entry requires significant space. By truncating to
//! 48 bits (6 bytes), we reduce storage from 77 GB to 13 GB while maintaining an
//! acceptably low collision probability.
//!
//! With ~900 million entries, the expected number of collisions is less than 1. For
//! password breach checking, a false positive (incorrectly marking a password as
//! breached) is harmless—it only causes a user to choose a different password.
//!
//! # Installation
//!
//! ```sh
//! cargo install hibp-bin-fetch
//! ```
//!
//! # Usage
//!
//! Download the full dataset:
//!
//! ```sh
//! hibp-bin-fetch --output ./hibp-data
//! ```
//!
//! Then use [hibp-verifier](https://crates.io/crates/hibp-verifier) to check passwords
//! against the downloaded dataset.

pub mod conversion;
pub mod error;
pub mod worker;

pub use conversion::{hex_to_nibble, line_to_sha1t48, prefix_to_hex};
pub use error::Error;
pub use worker::{get_completed_prefixes, worker};

/// Total number of prefix files (16^5 = 1,048,576)
pub const TOTAL_PREFIXES: u32 = 0x100000;
