//! HTTP response wrappers.
//!
//! Provides [`ScanResponse`], a high-level wrapper around HTTP responses
//! with convenient methods for accessing status, headers, and body content.

use reqwest::{
    header::{HeaderMap, HeaderName},
    StatusCode,
};

/// Final normalized HTTP response returned by `ScanClient` queries.
#[derive(Debug, Clone)]
pub struct ScanResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ScanResponse {
    pub(crate) async fn from_response(response: reqwest::Response) -> crate::Result<Self> {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// Returns the HTTP status code.
    ///
    /// Example:
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(StatusCode::OK, reqwest::header::HeaderMap::new(), b"ok".to_vec());
    /// assert_eq!(response.status(), StatusCode::OK);
    /// ```
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Access the parsed HTTP headers map.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Access the raw binary body bytes.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Attempt to parse the body as UTF-8 text.
    pub fn body_text(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Case-sensitive check if the body contains a specific substring.
    /// Falls back to lossy UTF-8 matching if necessary.
    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        match self.body_text() {
            Ok(text) => text.contains(needle),
            Err(_) => String::from_utf8_lossy(&self.body).contains(needle),
        }
    }

    /// Retrieve the raw string value of a specific response header.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        self.headers.get(name)?.to_str().ok()
    }

    /// Construct a response from already-materialized parts.
    ///
    /// This is mainly useful in tests and adapters that already have the body bytes.
    pub fn from_parts(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use reqwest::StatusCode;

    #[test]
    fn test_status_checks() {
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), vec![]);
        assert_eq!(resp.status(), StatusCode::OK);

        let resp2 = ScanResponse::from_parts(StatusCode::NOT_FOUND, HeaderMap::new(), vec![]);
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_header_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-custom-test"),
            HeaderValue::from_static("test-value"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let resp = ScanResponse::from_parts(StatusCode::OK, headers.clone(), vec![]);

        assert_eq!(resp.headers(), &headers);
        assert_eq!(resp.header_value("x-custom-test"), Some("test-value"));
        assert_eq!(resp.header_value("content-type"), Some("application/json"));
        assert_eq!(resp.header_value("non-existent"), None);
    }

    #[test]
    fn test_body_methods() {
        let body = b"hello world".to_vec();
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), body.clone());

        assert_eq!(resp.body_bytes(), b"hello world");
        assert_eq!(resp.body_text().unwrap(), "hello world");
        assert!(resp.contains("hello"));
        assert!(!resp.contains("goodbye"));
    }

    #[test]
    fn test_body_contains_lossy_utf8() {
        let mut body = b"hello ".to_vec();
        body.push(0xff); // invalid utf-8
        body.extend_from_slice(b" world");

        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), body);

        assert!(resp.body_text().is_err());
        assert!(resp.contains("hello"));
        assert!(resp.contains("world"));
    }
}
