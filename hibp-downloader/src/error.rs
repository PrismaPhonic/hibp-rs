use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP request failed for prefix {prefix}: {source}")]
    HttpRequest {
        prefix: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("HTTP {status} for prefix {prefix}")]
    HttpStatus { prefix: String, status: u16 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File '{path}' exists. Use --force to overwrite or --resume to continue.")]
    FileExists { path: PathBuf },

    #[error("Cannot use --resume and --force together")]
    InvalidArgs,

    #[error("Download failed after {retries} retries for prefix {prefix}")]
    MaxRetriesExceeded { prefix: String, retries: u32 },
}
