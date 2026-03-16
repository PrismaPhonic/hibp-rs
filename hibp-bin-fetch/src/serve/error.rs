use ntex::http::StatusCode;
use ntex::web::error::WebResponseError;
use ntex::web::{DefaultError, HttpRequest, HttpResponse};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("segment must be in range [0, of) and of must not be zero")]
    InvalidSegmentParams,

    #[error("since parameter is not a valid RFC 3339 timestamp")]
    InvalidSinceTimestamp,

    #[error("server data is not one cycle ahead of the requested since timestamp")]
    NotOneCycleBehind,

    #[error("internal server error: {0}")]
    Internal(#[from] std::io::Error),
}

#[derive(Serialize)]
struct ApiErrorBody {
    error: &'static str,
}

impl WebResponseError<DefaultError> for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidSegmentParams | Self::InvalidSinceTimestamp => StatusCode::BAD_REQUEST,
            Self::NotOneCycleBehind => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self, _: &HttpRequest) -> HttpResponse {
        if let Self::Internal(e) = self {
            tracing::error!(error = %e, "encode failed");
        }
        let code = match self {
            Self::InvalidSegmentParams => "invalid_segment_params",
            Self::InvalidSinceTimestamp => "invalid_since_timestamp",
            Self::NotOneCycleBehind => "not_one_cycle_behind",
            Self::Internal(_) => "internal_error",
        };
        HttpResponse::build(self.status_code()).json(&ApiErrorBody { error: code })
    }
}
