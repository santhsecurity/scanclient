//! HTTP Configuration loaders.
//!
//! Utilities for loading and serializing `scanclient` configuration from TOML.

use std::{collections::HashMap, fs, io, path::Path, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur when loading, parsing, or serializing HTTP configuration.
#[derive(Debug, Error)]
pub enum HttpConfigError {
    /// I/O failure while reading or writing config files.
    #[error("could not read config `{path}`: {source}. Fix: verify the file exists, is readable, and points to a TOML file with top-level `timeout_secs`, `proxy`, or `custom_headers` settings.")]
    Io {
        /// Path of the file that could not be read.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// TOML parsing failed.
    #[error("invalid HTTP config TOML: {0}. Fix: keep settings at the top level, for example `timeout_secs = 10` and `[custom_headers] X-Test = \"1\"`.")]
    Parse(#[from] toml::de::Error),
    /// TOML serialization failed.
    #[error("could not serialize HTTP config as TOML: {0}. Fix: remove unsupported values from `custom_headers` and retry serialization.")]
    Serialize(#[from] toml::ser::Error),
}

/// Configuration result type for crate-level config helpers.
pub type Result<T> = std::result::Result<T, HttpConfigError>;

/// Configuration blueprint for `ScanClient` instances.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpConfig {
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of automatic retries for transient faults.
    pub max_retries: u32,
    /// Base delay in milliseconds before exponential backoff retries.
    pub retry_delay_ms: u64,
    /// Maximum number of HTTP redirections to follow.
    pub max_redirects: usize,
    /// Upstream proxy URL override.
    pub proxy: Option<String>,
    /// Global User-Agent string to broadcast.
    pub user_agent: String,
    /// Global headers to attach to every outgoing request.
    pub custom_headers: HashMap<String, String>,
    /// Optional absolute hard-limit on requests per second per client instance.
    pub rate_limit_per_sec: Option<u32>,
    /// Whether retries are allowed for non-idempotent methods such as POST/PUT/PATCH/DELETE.
    pub retry_non_idempotent_methods: bool,
    /// Whether or not to perform strict TLS certificate validation.
    pub tls_verify: bool,
    /// Explicitly allow invalid TLS certificates.
    pub tls_accept_invalid_certs: bool,
    /// Explicitly allow invalid TLS hostnames.
    pub tls_accept_invalid_hostnames: bool,
    /// Maximum connection handshake timeout in seconds.
    pub connect_timeout_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_retries: 3,
            retry_delay_ms: 1_000,
            max_redirects: 5,
            proxy: None,
            user_agent: default_user_agent(),
            custom_headers: HashMap::new(),
            rate_limit_per_sec: None,
            retry_non_idempotent_methods: false,
            tls_verify: true,
            tls_accept_invalid_certs: false,
            tls_accept_invalid_hostnames: false,
            connect_timeout_secs: 5,
        }
    }
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (compatible; Santh/1.0; +https://santh.local/scanners)".to_string()
}

impl HttpConfig {
    /// Load config from a TOML file path.
    ///
    /// Example:
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("http.toml");
    /// std::fs::write(&path, "timeout_secs = 20\n").unwrap();
    /// let config = HttpConfig::load(&path).unwrap();
    /// assert_eq!(config.timeout_secs, 20);
    /// ```
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| HttpConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&content)
    }

    /// Parse config from a TOML string.
    ///
    /// Example:
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::from_toml("max_retries = 5").unwrap();
    /// assert_eq!(config.max_retries, 5);
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        Ok(toml::from_str(toml_str)?)
    }

    /// Serialize config to a TOML string.
    ///
    /// Example:
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let toml = HttpConfig::default().to_toml().unwrap();
    /// assert!(toml.contains("timeout_secs"));
    /// ```
    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Create a builder for [`HttpConfig`].
    ///
    /// Example:
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder().timeout_secs(30).build();
    /// assert_eq!(config.timeout_secs, 30);
    /// ```
    #[must_use]
    pub fn builder() -> HttpConfigBuilder {
        HttpConfigBuilder::default()
    }
}

/// Builder for [`HttpConfig`].
#[derive(Debug, Clone, Default)]
pub struct HttpConfigBuilder(HttpConfig);

impl HttpConfigBuilder {
    /// Set the overall request timeout in seconds.
    ///
    /// This timeout applies to the entire request, including connection
    /// establishment, sending the request, and reading the response.
    ///
    /// # Parameters
    /// - `value`: Timeout duration in seconds. Must be between 1 and 86,400.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .timeout_secs(30)
    ///     .build();
    /// assert_eq!(config.timeout_secs, 30);
    /// ```
    #[must_use]
    pub fn timeout_secs(mut self, value: u64) -> Self {
        self.0.timeout_secs = value;
        self
    }

    /// Set the maximum retry count for failed requests.
    ///
    /// The client will automatically retry requests that fail due to
    /// timeouts, connection errors, or 5xx server responses.
    ///
    /// # Parameters
    /// - `value`: Maximum number of retry attempts. Set to 0 to disable retries.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .max_retries(5)
    ///     .build();
    /// assert_eq!(config.max_retries, 5);
    /// ```
    #[must_use]
    pub fn max_retries(mut self, value: u32) -> Self {
        self.0.max_retries = value;
        self
    }

    /// Set the base retry delay in milliseconds.
    ///
    /// The actual delay between retries uses exponential backoff,
    /// calculated as `retry_delay_ms * 2^attempt_number`.
    ///
    /// # Parameters
    /// - `value`: Base delay in milliseconds. Must be between 1 and 60,000.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .retry_delay_ms(500)
    ///     .build();
    /// assert_eq!(config.retry_delay_ms, 500);
    /// ```
    #[must_use]
    pub fn retry_delay_ms(mut self, value: u64) -> Self {
        self.0.retry_delay_ms = value;
        self
    }

    /// Set the maximum number of redirects to follow.
    ///
    /// When the server returns a redirect response (3xx status code),
    /// the client will automatically follow up to this many redirects.
    ///
    /// # Parameters
    /// - `value`: Maximum number of redirects. Set to 0 to disable redirect following.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .max_redirects(3)
    ///     .build();
    /// assert_eq!(config.max_redirects, 3);
    /// ```
    #[must_use]
    pub fn max_redirects(mut self, value: usize) -> Self {
        self.0.max_redirects = value;
        self
    }

    /// Set the proxy URL for all requests.
    ///
    /// Supported proxy schemes: `http`, `https`, `socks5`, `socks5h`.
    /// Authentication can be included in the URL: `http://user:pass@proxy:8080`.
    ///
    /// # Parameters
    /// - `value`: The proxy URL as a string.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .proxy("http://127.0.0.1:8080")
    ///     .build();
    /// assert_eq!(config.proxy, Some("http://127.0.0.1:8080".to_string()));
    /// ```
    #[must_use]
    pub fn proxy(mut self, value: impl Into<String>) -> Self {
        self.0.proxy = Some(value.into());
        self
    }

    /// Set the User-Agent header for all requests.
    ///
    /// The User-Agent identifies the client to the server. This value
    /// is sent with every request and cannot be empty.
    ///
    /// # Parameters
    /// - `value`: The User-Agent string.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .user_agent("MyScanner/1.0")
    ///     .build();
    /// assert_eq!(config.user_agent, "MyScanner/1.0".to_string());
    /// ```
    #[must_use]
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.0.user_agent = value.into();
        self
    }

    /// Replace the custom headers map for all requests.
    ///
    /// These headers are sent with every request in addition to the
    /// User-Agent header. Header names must be valid HTTP header names.
    ///
    /// # Parameters
    /// - `value`: A `HashMap` of header names to header values.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// use scanclient::HttpConfig;
    ///
    /// let mut headers = HashMap::new();
    /// headers.insert("X-API-Key".to_string(), "secret123".to_string());
    ///
    /// let config = HttpConfig::builder()
    ///     .custom_headers(headers)
    ///     .build();
    /// assert_eq!(config.custom_headers.get("X-API-Key"), Some(&"secret123".to_string()));
    /// ```
    #[must_use]
    pub fn custom_headers(mut self, value: HashMap<String, String>) -> Self {
        self.0.custom_headers = value;
        self
    }

    /// Set the rate limit for requests per second.
    ///
    /// When set, the client will limit outgoing requests to the specified
    /// rate using a token bucket algorithm. This is useful for avoiding
    /// overwhelming target servers.
    ///
    /// # Parameters
    /// - `value`: Maximum requests per second, or `None` to disable rate limiting.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .rate_limit_per_sec(Some(10))
    ///     .build();
    /// assert_eq!(config.rate_limit_per_sec, Some(10));
    /// ```
    #[must_use]
    pub fn rate_limit_per_sec(mut self, value: Option<u32>) -> Self {
        self.0.rate_limit_per_sec = value;
        self
    }

    /// Allow retries for non-idempotent HTTP methods.
    ///
    /// By default, only idempotent methods (GET, HEAD, OPTIONS, TRACE,
    /// PUT, DELETE) are retried. Enabling this allows POST, PATCH, and
    /// other non-idempotent methods to be retried as well.
    ///
    /// # Parameters
    /// - `value`: `true` to allow retries for all methods, `false` for idempotent only.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .retry_non_idempotent_methods(true)
    ///     .build();
    /// assert!(config.retry_non_idempotent_methods);
    /// ```
    #[must_use]
    pub fn retry_non_idempotent_methods(mut self, value: bool) -> Self {
        self.0.retry_non_idempotent_methods = value;
        self
    }

    /// Enable or disable TLS certificate verification.
    ///
    /// When enabled (default), the client verifies that the server's
    /// certificate is valid and trusted. Disabling this is insecure
    /// and should only be done for testing or when connecting to
    /// servers with self-signed certificates.
    ///
    /// This setting is mutually exclusive with `tls_accept_invalid_certs`
    /// and `tls_accept_invalid_hostnames`.
    ///
    /// # Parameters
    /// - `value`: `true` to enable verification, `false` to disable.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .tls_verify(false)
    ///     .tls_accept_invalid_certs(true)
    ///     .build();
    /// assert!(!config.tls_verify);
    /// ```
    #[must_use]
    pub fn tls_verify(mut self, value: bool) -> Self {
        self.0.tls_verify = value;
        self
    }

    /// Allow connections to servers with invalid TLS certificates.
    ///
    /// When enabled, the client accepts any TLS certificate,
    /// including expired, self-signed, or otherwise invalid certs.
    /// This is insecure and should only be used for testing.
    ///
    /// Must be used together with `tls_verify(false)`.
    ///
    /// # Parameters
    /// - `value`: `true` to accept invalid certificates.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .tls_verify(false)
    ///     .tls_accept_invalid_certs(true)
    ///     .build();
    /// assert!(config.tls_accept_invalid_certs);
    /// ```
    #[must_use]
    pub fn tls_accept_invalid_certs(mut self, value: bool) -> Self {
        self.0.tls_accept_invalid_certs = value;
        self
    }

    /// Allow connections where the TLS certificate hostname doesn't match.
    ///
    /// When enabled, the client accepts certificates even if the hostname
    /// in the certificate doesn't match the requested URL. This is insecure
    /// and should only be used for testing.
    ///
    /// Must be used together with `tls_verify(false)`.
    ///
    /// # Parameters
    /// - `value`: `true` to accept hostname mismatches.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .tls_verify(false)
    ///     .tls_accept_invalid_hostnames(true)
    ///     .build();
    /// assert!(config.tls_accept_invalid_hostnames);
    /// ```
    #[must_use]
    pub fn tls_accept_invalid_hostnames(mut self, value: bool) -> Self {
        self.0.tls_accept_invalid_hostnames = value;
        self
    }

    /// Set the connection establishment timeout in seconds.
    ///
    /// This timeout applies only to establishing the TCP connection,
    /// not the entire request. It is typically shorter than the
    /// overall request timeout.
    ///
    /// # Parameters
    /// - `value`: Connection timeout in seconds. Must be between 1 and 86,400.
    ///
    /// # Returns
    /// The builder for method chaining.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .connect_timeout_secs(5)
    ///     .build();
    /// assert_eq!(config.connect_timeout_secs, 5);
    /// ```
    #[must_use]
    pub fn connect_timeout_secs(mut self, value: u64) -> Self {
        self.0.connect_timeout_secs = value;
        self
    }

    /// Finish building the configuration.
    ///
    /// Consumes the builder and returns a fully configured `HttpConfig`
    /// that can be used to create a `ScanClient`.
    ///
    /// # Returns
    /// A new `HttpConfig` instance with all the configured settings.
    ///
    /// # Example
    /// ```rust
    /// use scanclient::HttpConfig;
    ///
    /// let config = HttpConfig::builder()
    ///     .timeout_secs(30)
    ///     .max_retries(5)
    ///     .user_agent("MyScanner/1.0")
    ///     .build();
    /// ```
    #[must_use]
    pub fn build(self) -> HttpConfig {
        self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::uninlined_format_args)]

    use super::{HttpConfig, HttpConfigError};

    #[test]
    fn defaults_match_contract() {
        let config = HttpConfig::default();

        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1_000);
        assert_eq!(config.max_redirects, 5);
        assert_eq!(config.proxy, None);
        assert_eq!(
            config.user_agent,
            "Mozilla/5.0 (compatible; Santh/1.0; +https://santh.local/scanners)"
        );
        assert!(config.custom_headers.is_empty());
        assert_eq!(config.rate_limit_per_sec, None);
        assert!(config.tls_verify);
        assert_eq!(config.connect_timeout_secs, 5);
    }

    #[test]
    fn parses_partial_toml_with_defaults() {
        let raw = r#"
timeout_secs = 30
max_retries = 5
proxy = "http://127.0.0.1:8080"
rate_limit_per_sec = 8
tls_verify = false

[custom_headers]
X-Scanner = "karyx"
"#;

        let config: HttpConfig = toml::from_str(raw).expect("config should parse");

        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay_ms, 1_000);
        assert_eq!(config.max_redirects, 5);
        assert_eq!(config.proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(config.rate_limit_per_sec, Some(8));
        assert!(!config.tls_verify);
        assert_eq!(
            config.custom_headers.get("X-Scanner").map(String::as_str),
            Some("karyx")
        );
    }

    #[test]
    fn from_toml_convenience() {
        let config = HttpConfig::from_toml("timeout_secs = 42").unwrap();
        assert_eq!(config.timeout_secs, 42);
        assert_eq!(config.max_retries, 3); // default preserved
    }

    #[test]
    fn to_toml_round_trip() {
        let original = HttpConfig::default();
        let toml_str = original.to_toml().unwrap();
        let parsed = HttpConfig::from_toml(&toml_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let config = HttpConfig::from_toml("").unwrap();
        assert_eq!(config, HttpConfig::default());
    }

    #[test]
    fn invalid_toml_returns_error() {
        assert!(HttpConfig::from_toml("{{invalid").is_err());
    }

    #[test]
    fn load_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "timeout_secs = 99\n").unwrap();
        let config = HttpConfig::load(&path).unwrap();
        assert_eq!(config.timeout_secs, 99);
    }

    #[test]
    fn load_missing_file_errors() {
        let result = HttpConfig::load(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_pattern() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Test".to_string(), "Builder".to_string());

        let config = HttpConfig::builder()
            .timeout_secs(45)
            .max_retries(10)
            .retry_delay_ms(500)
            .max_redirects(2)
            .proxy("http://localhost:8888")
            .user_agent("CustomAgent")
            .custom_headers(headers.clone())
            .rate_limit_per_sec(Some(100))
            .tls_verify(false)
            .connect_timeout_secs(15)
            .build();

        assert_eq!(config.timeout_secs, 45);
        assert_eq!(config.max_retries, 10);
        assert_eq!(config.retry_delay_ms, 500);
        assert_eq!(config.max_redirects, 2);
        assert_eq!(config.proxy.as_deref(), Some("http://localhost:8888"));
        assert_eq!(config.user_agent, "CustomAgent");
        assert_eq!(config.custom_headers, headers);
        assert_eq!(config.rate_limit_per_sec, Some(100));
        assert!(!config.tls_verify);
        assert_eq!(config.connect_timeout_secs, 15);
    }

    #[test]
    fn test_error_display() {
        let io_err = HttpConfigError::Io {
            path: std::path::PathBuf::from("/fake/path.toml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        let io_str = format!("{}", io_err);
        assert!(io_str.contains("/fake/path.toml"));
        assert!(io_str.contains("file not found"));
        assert!(io_str.contains("Fix:"));

        let parse_err = HttpConfig::from_toml("invalid = \n").unwrap_err();
        let parse_str = format!("{}", parse_err);
        assert!(parse_str.contains("invalid HTTP config TOML:"));
        assert!(parse_str.contains("Fix: keep settings at the top level"));
    }

    #[test]
    fn load_with_empty_file_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        let config = HttpConfig::load(&path).unwrap();
        assert_eq!(config, HttpConfig::default());
    }

    #[test]
    fn load_with_unicode_path_and_unicode_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("設定.toml");
        let raw = r#"
user_agent = "scanner/日本語"
[custom_headers]
X-World = "Привет世界"
"#;
        std::fs::write(&path, raw).unwrap();
        let config = HttpConfig::load(&path).unwrap();
        assert_eq!(config.user_agent, "scanner/日本語");
        assert_eq!(
            config.custom_headers.get("X-World").map(String::as_str),
            Some("Привет世界")
        );
    }

    #[test]
    fn from_toml_rejects_null_byte() {
        let result = HttpConfig::from_toml("user_agent = \"a\0b\"");
        assert!(result.is_err());
    }

    #[test]
    fn from_toml_with_huge_input_fails_gracefully() {
        let mut huge = String::from("timeout_secs = 1\n");
        huge.push_str("[custom_headers]\n");
        for i in 0..5_000 {
            huge.push_str(&format!("X{i} = \"{}\"\n", "A".repeat(50)));
        }
        let result = HttpConfig::from_toml(&huge);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.timeout_secs, 1);
        assert!(parsed.custom_headers.len() >= 5_000);
    }

    #[test]
    fn to_toml_preserves_unicode_and_empty_values() {
        let mut config = HttpConfig::default();
        config.user_agent = "agent/🌐".to_string();
        config.custom_headers.insert("X-Empty".to_string(), String::new());
        config
            .custom_headers
            .insert("X-Emoji".to_string(), "🎉".to_string());
        let toml = config.to_toml().unwrap();
        let parsed = HttpConfig::from_toml(&toml).unwrap();
        assert_eq!(parsed.user_agent, "agent/🌐");
        assert_eq!(
            parsed.custom_headers.get("X-Empty").map(String::as_str),
            Some("")
        );
        assert_eq!(
            parsed.custom_headers.get("X-Emoji").map(String::as_str),
            Some("🎉")
        );
    }

    #[test]
    fn builder_supports_empty_proxy_when_set_explicitly() {
        let config = HttpConfig::builder().proxy("").build();
        assert_eq!(config.proxy.as_deref(), Some(""));
    }

    #[test]
    fn builder_sets_retry_non_idempotent_methods_flag() {
        let config = HttpConfig::builder()
            .retry_non_idempotent_methods(true)
            .build();
        assert!(config.retry_non_idempotent_methods);
    }

    #[test]
    fn builder_sets_tls_exception_flags() {
        let config = HttpConfig::builder()
            .tls_verify(false)
            .tls_accept_invalid_certs(true)
            .tls_accept_invalid_hostnames(true)
            .build();
        assert!(!config.tls_verify);
        assert!(config.tls_accept_invalid_certs);
        assert!(config.tls_accept_invalid_hostnames);
    }

    #[test]
    fn builder_sets_rate_limit_zero_value() {
        let config = HttpConfig::builder().rate_limit_per_sec(Some(0)).build();
        assert_eq!(config.rate_limit_per_sec, Some(0));
    }

    #[test]
    fn from_toml_with_empty_header_key_round_trips() {
        let raw = r#"
[custom_headers]
"" = "bad"
"#;
        let result = HttpConfig::from_toml(raw);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.custom_headers.get("").map(String::as_str), Some("bad"));
    }
}
