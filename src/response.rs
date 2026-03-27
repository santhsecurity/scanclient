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

    /// Access the HTTP response headers.
    ///
    /// Returns a reference to the `HeaderMap` containing all response headers.
    /// Use `header_value()` for a convenient way to access specific headers by name.
    ///
    /// # Returns
    /// A reference to the `HeaderMap` containing all response headers.
    ///
    /// # Example
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(
    /// #     StatusCode::OK,
    /// #     reqwest::header::HeaderMap::new(),
    /// #     b"ok".to_vec()
    /// # );
    /// let headers = response.headers();
    /// for (name, value) in headers.iter() {
    ///     println!("{}: {:?}", name, value);
    /// }
    /// ```
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Access the raw response body as bytes.
    ///
    /// Returns a byte slice containing the full response body.
    /// For text responses, consider using `body_text()` instead.
    ///
    /// # Returns
    /// A byte slice (`&[u8]`) containing the response body.
    ///
    /// # Example
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(
    /// #     StatusCode::OK,
    /// #     reqwest::header::HeaderMap::new(),
    /// #     b"Hello, World!".to_vec()
    /// # );
    /// let bytes = response.body_bytes();
    /// assert_eq!(bytes, b"Hello, World!");
    /// ```
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Parse the response body as UTF-8 text.
    ///
    /// Attempts to interpret the response body as a UTF-8 encoded string.
    /// Returns an error if the body contains invalid UTF-8 sequences.
    /// For lossy conversion, use `String::from_utf8_lossy()` on `body_bytes()`.
    ///
    /// # Returns
    /// - `Ok(&str)` if the body is valid UTF-8.
    /// - `Err(Utf8Error)` if the body contains invalid UTF-8 sequences.
    ///
    /// # Example
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(
    /// #     StatusCode::OK,
    /// #     reqwest::header::HeaderMap::new(),
    /// #     b"Hello, World!".to_vec()
    /// # );
    /// match response.body_text() {
    ///     Ok(text) => println!("Body: {}", text),
    ///     Err(e) => println!("Invalid UTF-8: {}", e),
    /// }
    /// ```
    pub fn body_text(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Check if the response body contains a specific substring.
    ///
    /// Performs a case-sensitive substring search on the response body.
    /// If the body is valid UTF-8, it searches the text directly.
    /// Otherwise, it falls back to lossy UTF-8 conversion for the search.
    ///
    /// # Parameters
    /// - `needle`: The substring to search for.
    ///
    /// # Returns
    /// `true` if the body contains the substring, `false` otherwise.
    ///
    /// # Example
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(
    /// #     StatusCode::OK,
    /// #     reqwest::header::HeaderMap::new(),
    /// #     b"Error: Invalid API key".to_vec()
    /// # );
    /// if response.contains("Error") {
    ///     println!("Response contains an error message");
    /// }
    /// ```
    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        match self.body_text() {
            Ok(text) => text.contains(needle),
            Err(_) => String::from_utf8_lossy(&self.body).contains(needle),
        }
    }

    /// Get the value of a specific response header.
    ///
    /// Retrieves a header value by its name. The search is case-insensitive
    /// as per HTTP specification. Returns `None` if the header is not present
    /// or if the header value contains non-UTF-8 bytes.
    ///
    /// # Parameters
    /// - `name`: The name of the header to retrieve (case-insensitive).
    ///
    /// # Returns
    /// - `Some(&str)` with the header value if found and valid UTF-8.
    /// - `None` if the header is not present or not valid UTF-8.
    ///
    /// # Example
    /// ```rust
    /// use reqwest::StatusCode;
    /// # let response = scanclient::ScanResponse::from_parts(
    /// #     StatusCode::OK,
    /// #     reqwest::header::HeaderMap::new(),
    /// #     b"ok".to_vec()
    /// # );
    /// if let Some(content_type) = response.header_value("Content-Type") {
    ///     println!("Content-Type: {}", content_type);
    /// }
    /// ```
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

    #[test]
    fn body_text_empty_body_is_ok() {
        let resp = ScanResponse::from_parts(StatusCode::NO_CONTENT, HeaderMap::new(), vec![]);
        assert_eq!(resp.body_text().unwrap(), "");
        assert!(!resp.contains("anything"));
    }

    #[test]
    fn body_text_handles_null_bytes() {
        let body = b"ab\0cd".to_vec();
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), body);
        let text = resp.body_text().unwrap();
        assert_eq!(text.len(), 5);
        assert!(resp.contains("ab"));
        assert!(resp.contains("cd"));
    }

    #[test]
    fn contains_handles_unicode_needles() {
        let body = "hello 世界 and Привет".as_bytes().to_vec();
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), body);
        assert!(resp.contains("世界"));
        assert!(resp.contains("Привет"));
        assert!(!resp.contains("不存在"));
    }

    #[test]
    fn header_value_invalid_header_name_returns_none() {
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), vec![]);
        assert_eq!(resp.header_value("bad\nheader"), None);
    }

    #[test]
    fn header_value_non_utf8_header_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-bin"),
            HeaderValue::from_bytes(&[0x66, 0x6f, 0x80, 0x6f]).unwrap(),
        );
        let resp = ScanResponse::from_parts(StatusCode::OK, headers, vec![]);
        assert_eq!(resp.header_value("x-bin"), None);
    }

    #[test]
    fn from_parts_with_huge_body_is_accessible() {
        let body = vec![b'A'; 2 * 1024 * 1024];
        let resp = ScanResponse::from_parts(StatusCode::OK, HeaderMap::new(), body);
        assert_eq!(resp.body_bytes().len(), 2 * 1024 * 1024);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn headers_reference_matches_inserted_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        headers.insert("x-b", HeaderValue::from_static("2"));
        let resp = ScanResponse::from_parts(StatusCode::OK, headers, vec![]);
        assert_eq!(resp.headers().len(), 2);
        assert_eq!(resp.header_value("x-a"), Some("1"));
        assert_eq!(resp.header_value("x-b"), Some("2"));
    }
}
