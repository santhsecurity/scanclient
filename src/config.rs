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
    #[must_use]
    pub fn timeout_secs(mut self, value: u64) -> Self {
        self.0.timeout_secs = value;
        self
    }

    /// Set the maximum retry count.
    #[must_use]
    pub fn max_retries(mut self, value: u32) -> Self {
        self.0.max_retries = value;
        self
    }

    /// Set the retry delay in milliseconds.
    #[must_use]
    pub fn retry_delay_ms(mut self, value: u64) -> Self {
        self.0.retry_delay_ms = value;
        self
    }

    /// Set the redirect limit.
    #[must_use]
    pub fn max_redirects(mut self, value: usize) -> Self {
        self.0.max_redirects = value;
        self
    }

    /// Set the proxy URL.
    #[must_use]
    pub fn proxy(mut self, value: impl Into<String>) -> Self {
        self.0.proxy = Some(value.into());
        self
    }

    /// Set the user agent.
    #[must_use]
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.0.user_agent = value.into();
        self
    }

    /// Replace the global header map.
    #[must_use]
    pub fn custom_headers(mut self, value: HashMap<String, String>) -> Self {
        self.0.custom_headers = value;
        self
    }

    /// Set the per-client request rate limit.
    #[must_use]
    pub fn rate_limit_per_sec(mut self, value: Option<u32>) -> Self {
        self.0.rate_limit_per_sec = value;
        self
    }

    /// Enable or disable strict TLS verification.
    #[must_use]
    pub fn tls_verify(mut self, value: bool) -> Self {
        self.0.tls_verify = value;
        self
    }

    /// Allow invalid TLS certificates.
    #[must_use]
    pub fn tls_accept_invalid_certs(mut self, value: bool) -> Self {
        self.0.tls_accept_invalid_certs = value;
        self
    }

    /// Allow invalid TLS hostnames.
    #[must_use]
    pub fn tls_accept_invalid_hostnames(mut self, value: bool) -> Self {
        self.0.tls_accept_invalid_hostnames = value;
        self
    }

    /// Set the connection timeout in seconds.
    #[must_use]
    pub fn connect_timeout_secs(mut self, value: u64) -> Self {
        self.0.connect_timeout_secs = value;
        self
    }

    /// Finish building the config.
    #[must_use]
    pub fn build(self) -> HttpConfig {
        self.0
    }
}

#[cfg(test)]
mod tests {
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
}
