use bytes::{BufMut as _, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use compact_str::CompactString;
use futures_util::StreamExt;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use tokio::io::AsyncRead;

use crate::error::Error;

static STATUS_PATH: &[u8] = b"/v1/status";
static CHANGED_PATH: &[u8] = b"/v1/changed";
static SEGMENT_PREFIX: &[u8] = b"/v1/segment?segment=";
static OF_PARAM: &[u8] = b"&of=";
static SINCE_PARAM: &[u8] = b"&since=";

// Max path+query: "/v1/segment?segment=254&of=255&since=2026-01-01T00:00:00Z" = 57 bytes
const SEGMENT_BUF_CAP: usize = 64;

pub struct Client {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    http_client: hyper_util::client::legacy::Client<HttpConnector, Empty<Bytes>>,
}

#[derive(Deserialize)]
pub struct Status {
    pub last_updated: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct Changed {
    pub last_updated: Option<DateTime<Utc>>,
    pub prev_last_updated: Option<DateTime<Utc>>,
    pub prefixes: Vec<CompactString>,
}

impl Client {
    pub fn new(base_url: &http::Uri) -> Result<Self, Error> {
        let scheme = base_url.scheme().ok_or(Error::InvalidServerUrl("missing scheme"))?.clone();
        let authority = base_url
            .authority()
            .ok_or(Error::InvalidServerUrl("missing authority"))?
            .clone();
        let http_client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build(HttpConnector::new());
        Ok(Self { scheme, authority, http_client })
    }

    fn uri(&self, pq: Bytes) -> http::Uri {
        let mut parts = http::uri::Parts::default();
        parts.scheme = Some(self.scheme.clone());
        parts.authority = Some(self.authority.clone());
        parts.path_and_query = Some(
            http::uri::PathAndQuery::from_maybe_shared(pq)
                .expect("caller ensures valid path-and-query bytes"),
        );
        http::Uri::from_parts(parts).expect("Uri from all parts is infallible")
    }

    async fn get(&self, pq: Bytes) -> Result<Bytes, Error> {
        let req = hyper::Request::get(self.uri(pq)).body(Empty::new())?;
        let resp = self.http_client.request(req).await?;
        if !resp.status().is_success() {
            return Err(Error::HttpStatus(resp.status()));
        }
        Ok(resp.into_body().collect().await?.to_bytes())
    }

    #[tracing::instrument(skip_all)]
    pub async fn status(&self) -> Result<Status, Error> {
        let bytes = self.get(Bytes::from_static(STATUS_PATH)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    #[tracing::instrument(skip_all)]
    pub async fn changed(&self) -> Result<Changed, Error> {
        let bytes = self.get(Bytes::from_static(CHANGED_PATH)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    #[tracing::instrument(skip(self))]
    pub async fn segment_stream(
        &self,
        segment: u8,
        of: u8,
        since: Option<&str>,
    ) -> Result<impl AsyncRead + Unpin + Send + 'static, Error> {
        let since_bytes = since.map_or(&[][..], str::as_bytes);
        let mut buf = BytesMut::with_capacity(SEGMENT_BUF_CAP + since_bytes.len());
        buf.extend_from_slice(SEGMENT_PREFIX);
        write_decimal(&mut buf, segment);
        buf.extend_from_slice(OF_PARAM);
        write_decimal(&mut buf, of);
        if !since_bytes.is_empty() {
            buf.extend_from_slice(SINCE_PARAM);
            buf.extend_from_slice(since_bytes);
        }

        let req = hyper::Request::get(self.uri(buf.freeze())).body(Empty::new())?;
        let resp = self.http_client.request(req).await?;

        if !resp.status().is_success() {
            return Err(Error::HttpStatus(resp.status()));
        }

        let body_stream = resp
            .into_body()
            .into_data_stream()
            .map(|res| res.map_err(std::io::Error::other));
        let reader = tokio_util::io::StreamReader::new(body_stream);
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(reader);
        Ok(decoder)
    }
}

fn write_decimal(buf: &mut BytesMut, mut n: u8) {
    let start = buf.len();
    let mut count = 0;

    loop {
        buf.put_u8(b'0' + (n % 10));
        count += 1;

        n /= 10;
        if n == 0 {
            break;
        }
    }

    buf[start..start + count].reverse();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_uri_no_since() {
        let client = Client::new(&"http://127.0.0.1:8765".parse().unwrap()).unwrap();
        let mut buf = BytesMut::with_capacity(SEGMENT_BUF_CAP);
        buf.extend_from_slice(SEGMENT_PREFIX);
        write_decimal(&mut buf, 3);
        buf.extend_from_slice(OF_PARAM);
        write_decimal(&mut buf, 16);
        let uri = client.uri(buf.freeze());
        assert_eq!(
            uri.to_string(),
            "http://127.0.0.1:8765/v1/segment?segment=3&of=16"
        );
    }

    #[test]
    fn segment_uri_with_since() {
        let client = Client::new(&"http://127.0.0.1:8765".parse().unwrap()).unwrap();
        let mut buf = BytesMut::with_capacity(SEGMENT_BUF_CAP);
        buf.extend_from_slice(SEGMENT_PREFIX);
        write_decimal(&mut buf, 0);
        buf.extend_from_slice(OF_PARAM);
        write_decimal(&mut buf, 1);
        buf.extend_from_slice(SINCE_PARAM);
        buf.extend_from_slice(b"2026-01-01T00:00:00Z");
        let uri = client.uri(buf.freeze());
        assert_eq!(
            uri.to_string(),
            "http://127.0.0.1:8765/v1/segment?segment=0&of=1&since=2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn new_rejects_missing_scheme() {
        assert!(Client::new(&http::Uri::from_static("/no-scheme")).is_err());
    }
}
