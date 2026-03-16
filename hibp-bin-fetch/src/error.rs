use std::io;
use std::path::PathBuf;

use compact_str::CompactString;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP request failed for prefix {prefix}: {source}")]
    HttpRequest {
        prefix: CompactString,
        #[source]
        source: reqwest::Error,
    },

    #[error("HTTP {status} for prefix {prefix}")]
    HttpStatus { prefix: CompactString, status: u16 },

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("File '{path}' exists. Use --force to overwrite or --resume to continue.")]
    FileExists { path: PathBuf },

    #[error("Cannot use --resume and --force together")]
    InvalidArgs,

    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("Download failed after {retries} retries for prefix {prefix}")]
    MaxRetriesExceeded { prefix: CompactString, retries: u32 },
}
