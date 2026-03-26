# scanclient

HTTP client configuration for security scanners. Wraps reqwest with retries, rate limiting, proxy support, custom headers, and TLS settings. Load everything from a TOML file.

```rust
use scanclient::HttpConfig;

let config = HttpConfig::from_toml(r#"
    timeout_secs = 30
    max_retries = 5
    proxy = "http://127.0.0.1:8080"
    tls_verify = false
    rate_limit_per_sec = 10

    [custom_headers]
    X-Bug-Bounty = "authorized"
"#).unwrap();
```

## Why not just use reqwest directly?

You can. scanclient is for when you're building a scanner and want the same config pattern every time: timeouts, retries with backoff, rate limiting, proxy, custom headers, TLS options. Instead of wiring this up from scratch in every project, load a TOML file.

## Configuration

Every field has a sensible default. Override what you need:

| Field | Default | What it does |
|-------|---------|-------------|
| timeout_secs | 10 | Request timeout |
| max_retries | 3 | Retry on failure |
| retry_delay_ms | 1000 | Delay between retries |
| max_redirects | 5 | Follow redirects |
| proxy | None | HTTP proxy URL |
| user_agent | Mozilla/5.0... | Request User-Agent |
| rate_limit_per_sec | None | Max requests per second |
| tls_verify | true | Verify TLS certificates |
| connect_timeout_secs | 5 | Connection timeout |

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/scanclient.svg)](https://crates.io/crates/scanclient)
[![docs.rs](https://docs.rs/scanclient/badge.svg)](https://docs.rs/scanclient)
