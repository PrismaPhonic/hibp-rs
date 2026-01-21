pub mod conversion;
pub mod error;
pub mod worker;

pub use conversion::{hex_to_nibble, line_to_sha1t64, prefix_to_hex};
pub use error::Error;
pub use worker::{MAX_RETRIES, RETRY_BASE_DELAY_MS, get_completed_prefixes, worker};

/// Total number of prefix files (16^5 = 1,048,576)
pub const TOTAL_PREFIXES: u32 = 0x100000;
