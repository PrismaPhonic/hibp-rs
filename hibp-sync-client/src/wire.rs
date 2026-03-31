use async_stream::try_stream;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::Error;

pub struct WireEntry {
    pub prefix: [u8; 5],
    pub content: Vec<u8>,
}

pub fn decode_segment_stream<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
) -> impl Stream<Item = Result<WireEntry, Error>> + Send + 'static {
    try_stream! {
        let mut count_buf = [0u8; 4];
        reader.read_exact(&mut count_buf).await.map_err(|e| Error::Decode(format!("failed to read count: {e}")))?;
        let count = u32::from_le_bytes(count_buf) as usize;

        const MAX_SEGMENT_ENTRIES: usize = 1_048_576;
        if count > MAX_SEGMENT_ENTRIES {
            Err(Error::Decode(format!(
                "entry count {count} exceeds maximum {MAX_SEGMENT_ENTRIES}"
            )))?;
        }

        for i in 0..count {
            let mut prefix = [0u8; 5];
            reader.read_exact(&mut prefix).await.map_err(|e| Error::Decode(format!("entry {i}: truncated header: {e}")))?;

            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf).await.map_err(|e| Error::Decode(format!("entry {i}: truncated header: {e}")))?;
            let content_len = u32::from_le_bytes(len_buf) as usize;

            let mut content = vec![0u8; content_len];
            reader.read_exact(&mut content).await.map_err(|e| Error::Decode(format!("entry {i}: content truncated: {e}")))?;

            yield WireEntry { prefix, content };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_bytes(entries: &[([u8; 5], &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (prefix, content) in entries {
            buf.extend_from_slice(prefix);
            buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
            buf.extend_from_slice(content);
        }
        buf
    }

    #[tokio::test]
    async fn decode_empty_segment() {
        let buf = wire_bytes(&[]);
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(buf));
        let mut stream = Box::pin(decode_segment_stream(reader));
        use futures_util::StreamExt;
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn decode_single_entry() {
        let buf = wire_bytes(&[(*b"A3C01", b"hello world" as &[u8])]);
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(buf));
        let mut stream = Box::pin(decode_segment_stream(reader));
        use futures_util::StreamExt;

        let entry = stream.next().await.unwrap().unwrap();
        assert_eq!(&entry.prefix, b"A3C01");
        assert_eq!(entry.content, b"hello world");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn decode_truncated_header() {
        // count=1 but only 4 bytes of the 9-byte entry header follow
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(b"A3C0"); // only 4 bytes of prefix (needs 5+4)

        let reader = tokio::io::BufReader::new(std::io::Cursor::new(buf));
        let mut stream = Box::pin(decode_segment_stream(reader));
        use futures_util::StreamExt;

        assert!(stream.next().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn decode_truncated_content() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(b"A3C01");
        buf.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        buf.extend_from_slice(b"short"); // only 5

        let reader = tokio::io::BufReader::new(std::io::Cursor::new(buf));
        let mut stream = Box::pin(decode_segment_stream(reader));
        use futures_util::StreamExt;

        assert!(stream.next().await.unwrap().is_err());
    }
}
