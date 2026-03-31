#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid server URL: {0}")]
    InvalidServerUrl(&'static str),

    #[error("HTTP request build error: {0}")]
    RequestBuild(#[from] http::Error),

    #[error("HTTP request error: {0}")]
    Request(#[from] hyper_util::client::legacy::Error),

    #[error("HTTP response read error: {0}")]
    ResponseRead(#[from] hyper::Error),

    #[error("HTTP error status: {0}")]
    HttpStatus(http::StatusCode),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("segment decode error: {0}")]
    Decode(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
}
