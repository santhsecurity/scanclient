//! Scanning HTTP client tuned for security tooling.

use std::{fmt, time::Duration};

use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT},
    redirect::Policy,
    Method, RequestBuilder,
};
use thiserror::Error;
use tokio::{time::sleep};
use tower::{
    limit::RateLimitLayer,
    service_fn,
    util::{BoxService, ServiceExt},
    BoxError, Service, ServiceBuilder,
};

use crate::{HttpConfig, ScanResponse};

/// Type alias for HTTP client operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during HTTP client instantiation or execution.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to configure or build the reqwest client internally.
    #[error("could not build HTTP client: {0}. Fix: verify `proxy`, `custom_headers`, TLS settings, and timeout values in `HttpConfig`.")]
    ClientBuild(#[source] reqwest::Error),
    /// Proxy string provided was invalid or unparseable.
    #[error("invalid proxy URL `{0}`. Fix: use a full proxy URL such as `http://127.0.0.1:8080` or `socks5h://127.0.0.1:9050`.")]
    InvalidProxy(String),
    /// TLS verification settings are contradictory or insecure without explicit opt-in.
    #[error("invalid TLS configuration. Fix: keep `tls_verify = true`, or explicitly set `tls_accept_invalid_certs` and/or `tls_accept_invalid_hostnames` when intentionally connecting to untrusted endpoints.")]
    InvalidTlsConfig,
    /// Timeout configuration is invalid.
    #[error("invalid `{field}` value `{value}`. Fix: use a value between 1 and {max} seconds.")]
    InvalidTimeout {
        /// The invalid field name.
        field: &'static str,
        /// The invalid value.
        value: u64,
        /// The maximum accepted value.
        max: u64,
    },
    /// Retry delay configuration is invalid.
    #[error("invalid retry delay `{value}`ms. Fix: use a value between 1ms and {max}ms.")]
    InvalidRetryDelay {
        /// The invalid retry delay.
        value: u64,
        /// The maximum accepted value.
        max: u64,
    },
    /// User agent configuration is invalid.
    #[error("invalid user agent. Fix: provide a non-empty HTTP-safe User-Agent string.")]
    InvalidUserAgent,
    /// Custom header name contained illegal characters.
    #[error(
        "invalid header name `{name}`. Fix: use an ASCII HTTP header name such as `X-Trace-Id`."
    )]
    InvalidHeaderName {
        /// The invalid header name.
        name: String,
    },
    /// Custom header value contained illegal characters.
    #[error("invalid header value for `{name}`. Fix: remove newlines and non-header-safe bytes from the configured value.")]
    InvalidHeaderValue {
        /// The invalid header value's key name.
        name: String,
    },
    /// Rate limiter configuration encountered an error.
    #[error("rate limit configuration failed: {0}. Fix: create the client inside a Tokio runtime and use a positive `rate_limit_per_sec` value.")]
    RateLimiter(BoxError),
    /// A required request could not be cloned for a retry attempt.
    #[error("request could not be cloned for retry. Fix: avoid streaming bodies for retried requests, or set `max_retries = 0` for one-shot uploads.")]
    UnclonableRequest,
    /// The maximum number of retry attempts was exhausted.
    #[error("request still failed after all retries. Fix: inspect the source error, increase `max_retries`, or reduce concurrency against the upstream service.")]
    RetryExhausted {
        /// The final underlying network or timeout error.
        #[source]
        source: reqwest::Error,
    },
    /// A generalized request error from reqwest.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
}

type RateGate = tower::buffer::Buffer<BoxService<(), (), BoxError>, ()>;

const MAX_TIMEOUT_SECS: u64 = 86_400;
const MAX_RETRY_DELAY_MS: u64 = 60_000;

/// A high-performance, retry-aware asynchronous HTTP client optimized for security scanning.
#[derive(Clone)]
pub struct ScanClient {
    client: reqwest::Client,
    config: HttpConfig,
    rate_gate: Option<RateGate>,
}

impl fmt::Debug for ScanClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ScanClient {
    /// Instantiate the client from a predefined `HttpConfig`.
    ///
    /// Example:
    /// ```rust
    /// use scanclient::{HttpConfig, ScanClient};
    ///
    /// let client = ScanClient::from_config(HttpConfig::default()).unwrap();
    /// let _ = client;
    /// ```
    pub fn from_config(config: HttpConfig) -> Result<Self> {
        let client = build_client(&config)?;
        let rate_gate = build_rate_gate(config.rate_limit_per_sec)?;

        Ok(Self {
            client,
            config,
            rate_gate,
        })
    }

    /// Perform an asynchronous GET request to the specified URL.
    ///
    /// Example:
    /// ```rust,no_run
    /// use scanclient::{HttpConfig, ScanClient};
    ///
    /// #[tokio::main]
    /// async fn main() -> scanclient::Result<()> {
    ///     let client = ScanClient::from_config(HttpConfig::default())?;
    ///     let _response = client.get("https://example.com").await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn get(&self, url: &str) -> Result<ScanResponse> {
        self.execute(self.client.get(url)).await
    }

    /// Perform an asynchronous HEAD request to the specified URL.
    pub async fn head(&self, url: &str) -> Result<ScanResponse> {
        self.execute(self.client.head(url)).await
    }

    /// Perform an asynchronous POST request with a body payload.
    pub async fn post<B>(&self, url: &str, body: B) -> Result<ScanResponse>
    where
        B: Into<reqwest::Body>,
    {
        self.execute(self.client.post(url).body(body)).await
    }

    /// Create a custom `RequestBuilder` utilizing the internal connection pool.
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
    }

    /// Execute a constructed request through the retry and rate-limiting pipeline.
    pub async fn execute(&self, builder: RequestBuilder) -> Result<ScanResponse> {
        let response = self.execute_raw(builder).await?;
        ScanResponse::from_response(response).await
    }

    async fn execute_raw(&self, builder: RequestBuilder) -> Result<reqwest::Response> {
        let max_attempts = self.config.max_retries.saturating_add(1);

        let mut attempt = 0;
        loop {
            self.acquire_rate_slot().await?;

            let request = builder.try_clone().ok_or(Error::UnclonableRequest)?;
            match request.send().await {
                Ok(response)
                    if should_retry_status(response.status()) && attempt + 1 < max_attempts =>
                {
                    sleep(backoff_delay(self.config.retry_delay_ms, attempt)).await;
                }
                Ok(response) => return Ok(response),
                Err(error) if should_retry_error(&error) && attempt + 1 < max_attempts => {
                    sleep(backoff_delay(self.config.retry_delay_ms, attempt)).await;
                }
                Err(error) if should_retry_error(&error) => {
                    return Err(Error::RetryExhausted { source: error });
                }
                Err(error) => return Err(Error::Request(error)),
            }
            attempt += 1;
        }
    }

    async fn acquire_rate_slot(&self) -> Result<()> {
        let Some(rate_gate) = &self.rate_gate else {
            return Ok(());
        };

        let mut gate = rate_gate.clone();
        gate.ready().await.map_err(Error::RateLimiter)?;
        gate.call(()).await.map_err(Error::RateLimiter)?;
        Ok(())
    }
}

fn build_client(config: &HttpConfig) -> Result<reqwest::Client> {
    validate_timeouts(config)?;
    validate_tls_config(config)?;
    validate_user_agent(config)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&config.user_agent).map_err(|_| Error::InvalidHeaderValue {
            name: USER_AGENT.as_str().to_string(),
        })?,
    );

    for (name, value) in &config.custom_headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::InvalidHeaderName { name: name.clone() })?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| Error::InvalidHeaderValue { name: name.clone() })?;
        headers.insert(header_name, header_value);
    }

    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(config.timeout_secs))
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .redirect(Policy::limited(config.max_redirects))
        .danger_accept_invalid_certs(config.tls_accept_invalid_certs)
        .danger_accept_invalid_hostnames(config.tls_accept_invalid_hostnames);

    if let Some(proxy) = &config.proxy {
        validate_proxy_url(proxy)?;
        let reqwest_proxy =
            reqwest::Proxy::all(proxy).map_err(|_| Error::InvalidProxy(proxy.clone()))?;
        builder = builder.proxy(reqwest_proxy);
    }

    builder.build().map_err(Error::ClientBuild)
}

fn validate_tls_config(config: &HttpConfig) -> Result<()> {
    if config.tls_verify {
        if config.tls_accept_invalid_certs || config.tls_accept_invalid_hostnames {
            return Err(Error::InvalidTlsConfig);
        }
        return Ok(());
    }

    if config.tls_accept_invalid_certs || config.tls_accept_invalid_hostnames {
        return Ok(());
    }

    Err(Error::InvalidTlsConfig)
}

fn validate_timeouts(config: &HttpConfig) -> Result<()> {
    for (field, value) in [
        ("timeout_secs", config.timeout_secs),
        ("connect_timeout_secs", config.connect_timeout_secs),
    ] {
        if value == 0 || value > MAX_TIMEOUT_SECS {
            return Err(Error::InvalidTimeout {
                field,
                value,
                max: MAX_TIMEOUT_SECS,
            });
        }
    }

    if config.retry_delay_ms == 0 || config.retry_delay_ms > MAX_RETRY_DELAY_MS {
        return Err(Error::InvalidRetryDelay {
            value: config.retry_delay_ms,
            max: MAX_RETRY_DELAY_MS,
        });
    }

    Ok(())
}

fn validate_user_agent(config: &HttpConfig) -> Result<()> {
    if config.user_agent.trim().is_empty() {
        return Err(Error::InvalidUserAgent);
    }

    Ok(())
}

fn validate_proxy_url(proxy: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(proxy).map_err(|_| Error::InvalidProxy(proxy.to_string()))?;
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => return Err(Error::InvalidProxy(proxy.to_string())),
    }
    if parsed.host_str().is_none() {
        return Err(Error::InvalidProxy(proxy.to_string()));
    }
    if !parsed.path().is_empty() && parsed.path() != "/" {
        return Err(Error::InvalidProxy(proxy.to_string()));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::InvalidProxy(proxy.to_string()));
    }
    Ok(())
}

fn build_rate_gate(limit: Option<u32>) -> Result<Option<RateGate>> {
    let Some(limit_val) = limit else {
        return Ok(None);
    };
    let per_second = limit_val.max(1);

    if tokio::runtime::Handle::try_current().is_err() {
        return Err(Error::RateLimiter(
            "Cannot construct rate-limited ScanClient outside of a tokio runtime context".into(),
        ));
    }

    let service = ServiceBuilder::new()
        .layer(RateLimitLayer::new(
            u64::from(per_second),
            Duration::from_secs(1),
        ))
        .service(service_fn(|()| async move { Ok::<(), BoxError>(()) }));

    let boxed = BoxService::new(service);
    let buffer = tower::buffer::Buffer::new(boxed, per_second as usize * 100);

    Ok(Some(buffer))
}

fn should_retry_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn should_retry_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
}

fn backoff_delay(base_ms: u64, attempt: u32) -> Duration {
    let factor = 1_u64 << attempt.min(16);
    Duration::from_millis(base_ms.min(MAX_RETRY_DELAY_MS).saturating_mul(factor))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    use super::*;

    #[test]
    fn client_builds_from_defaults() {
        let client = ScanClient::from_config(HttpConfig::default()).expect("client should build");
        assert_eq!(client.config.max_retries, 3);
    }

    #[tokio::test]
    async fn retries_until_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let (address, server) = spawn_test_server(move |_| {
            let current = server_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if current < 3 {
                    http_response(500, &[("content-length", "5")], b"error")
                } else {
                    http_response(200, &[("content-length", "2")], b"ok")
                }
            }
        })
        .await;
        tokio::spawn(server);

        let client = ScanClient::from_config(HttpConfig {
            max_retries: 4,
            retry_delay_ms: 10,
            ..HttpConfig::default()
        })
        .expect("client should build");

        let response = client
            .get(&format!("http://{address}/health"))
            .await
            .expect("request should eventually succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.body_text().expect("utf8 body"), "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn request_builder_uses_default_headers() {
        let captured = Arc::new(Mutex::new(HashMap::<String, String>::new()));
        let captured_headers = captured.clone();
        let (address, server) = spawn_test_server(move |headers| {
            let captured_headers = captured_headers.clone();
            async move {
                *captured_headers.lock().await = headers;
                http_response(200, &[("content-length", "7")], b"headers")
            }
        })
        .await;
        tokio::spawn(server);

        let mut custom_headers = HashMap::new();
        custom_headers.insert("x-scanner".to_string(), "wafrift".to_string());

        let client = ScanClient::from_config(HttpConfig {
            user_agent: "Mozilla/5.0 test".to_string(),
            custom_headers,
            ..HttpConfig::default()
        })
        .expect("client should build");

        let response = client
            .get(&format!("http://{address}/headers"))
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let headers = captured.lock().await;
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some("Mozilla/5.0 test")
        );
        assert_eq!(
            headers.get("x-scanner").map(String::as_str),
            Some("wafrift")
        );
    }

    async fn spawn_test_server<F, Fut>(
        handler: F,
    ) -> (SocketAddr, impl std::future::Future<Output = ()>)
    where
        F: Fn(HashMap<String, String>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let handler = Arc::new(handler);

        let server = async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(result) => result,
                    Err(_) => break,
                };
                let handler = handler.clone();

                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 4096];
                    let read = match stream.read(&mut buffer).await {
                        Ok(read) => read,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let headers = parse_headers(&request);
                    let response = handler(headers).await;
                    let _ = stream.write_all(&response).await;
                });
            }
        };

        (address, server)
    }

    fn parse_headers(raw_request: &str) -> HashMap<String, String> {
        raw_request
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect()
    }

    fn http_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "OK",
        };

        let mut response = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
        for (name, value) in headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn test_backoff_delay() {
        assert_eq!(backoff_delay(100, 0), Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(backoff_delay(100, 1), Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(backoff_delay(100, 2), Duration::from_millis(400)); // 100 * 2^2
        assert_eq!(backoff_delay(100, 16), Duration::from_millis(6553600)); // 100 * 2^16
        assert_eq!(backoff_delay(100, 20), Duration::from_millis(6553600)); // Max cap at 16
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        // Valid limit
        let config = HttpConfig {
            rate_limit_per_sec: Some(10),
            ..Default::default()
        };
        let client = ScanClient::from_config(config).unwrap();
        assert!(client.rate_gate.is_some());

        // No limit
        let config_no_limit = HttpConfig {
            rate_limit_per_sec: None,
            ..Default::default()
        };
        let client_no_limit = ScanClient::from_config(config_no_limit).unwrap();
        assert!(client_no_limit.rate_gate.is_none());
    }

    #[tokio::test]
    async fn test_max_retries_exhausted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let (address, server) = spawn_test_server(move |_| {
            let _ = server_attempts.fetch_add(1, Ordering::SeqCst);
            async move { http_response(500, &[("content-length", "5")], b"error") }
        })
        .await;
        tokio::spawn(server);

        let client = ScanClient::from_config(HttpConfig {
            max_retries: 2,
            retry_delay_ms: 5,
            ..HttpConfig::default()
        })
        .unwrap();

        let response = client.get(&format!("http://{address}/health")).await;

        // It should either return the final 500 response or an error, based on execute_raw logic
        // Current logic for 500 status returns the 500 response after all retries.
        let resp = response.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);

        // 1 initial try + 2 retries = 3 attempts
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_error_display_from_impls() {
        let err = Error::InvalidProxy("bad-proxy".to_string());
        let display_str = format!("{}", err);
        assert!(display_str.contains("invalid proxy URL `bad-proxy`"));

        let err2 = Error::InvalidHeaderName {
            name: "bad header".to_string(),
        };
        let display_str2 = format!("{}", err2);
        assert!(display_str2.contains("invalid header name `bad header`"));

        let err3 = Error::InvalidHeaderValue {
            name: "test-head".to_string(),
        };
        let display_str3 = format!("{}", err3);
        assert!(display_str3.contains("invalid header value for `test-head`"));

        let _ = Error::UnclonableRequest;
    }

    #[tokio::test]
    async fn test_head_and_post_requests() {
        let (address, server) = spawn_test_server(move |_headers| async move {
            http_response(200, &[("content-length", "2")], b"ok")
        })
        .await;
        tokio::spawn(server);

        let client = ScanClient::from_config(HttpConfig::default()).unwrap();

        // test HEAD
        let head_resp = client.head(&format!("http://{address}/")).await.unwrap();
        assert_eq!(head_resp.status(), reqwest::StatusCode::OK);

        // test POST
        let post_resp = client
            .post(&format!("http://{address}/"), "body")
            .await
            .unwrap();
        assert_eq!(post_resp.status(), reqwest::StatusCode::OK);
        assert_eq!(post_resp.body_text().unwrap(), "ok");
    }
}
