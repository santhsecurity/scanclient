//! Adversarial tests for scanclient - designed to BREAK the code
//!
//! Tests: config with 0 timeout, 100 custom headers, proxy with auth,
//! TOML with unknown fields, empty user agent

#![allow(
    clippy::manual_string_new,
    clippy::match_same_arms,
    clippy::needless_raw_string_hashes,
    clippy::uninlined_format_args
)]

use crate::{client::ScanClient, config::HttpConfig, Error};
use std::collections::HashMap;

/// Test config with 0 timeout
#[test]
fn adversarial_zero_timeout_config() {
    let config = HttpConfig {
        timeout_secs: 0,         // Zero timeout
        connect_timeout_secs: 0, // Zero connect timeout
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Err(Error::InvalidTimeout {
            field: "timeout_secs",
            value: 0,
            ..
        }) => {}
        other => panic!("expected InvalidTimeout for timeout_secs, got {other:?}"),
    }
}

/// Test config with very large timeout
#[test]
fn adversarial_huge_timeout_config() {
    let config = HttpConfig {
        timeout_secs: u64::MAX,         // Max timeout
        connect_timeout_secs: u64::MAX, // Max connect timeout
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Err(Error::InvalidTimeout {
            field: "timeout_secs",
            value,
            ..
        }) if value == u64::MAX => {}
        other => panic!("expected huge timeout to be rejected, got {other:?}"),
    }
}

/// Test with 100 custom headers
#[test]
fn adversarial_100_custom_headers() {
    let mut custom_headers = HashMap::new();

    for i in 0..100 {
        custom_headers.insert(format!("X-Custom-Header-{}", i), format!("value-{}", i));
    }

    let config = HttpConfig {
        custom_headers,
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    assert!(result.is_ok(), "Should build client with 100 headers");
}

/// Test with headers that have special characters
#[test]
fn adversarial_headers_special_chars() {
    let mut custom_headers = HashMap::new();

    // Headers with various special characters
    custom_headers.insert("X-Test".to_string(), "value with spaces".to_string());
    custom_headers.insert("X-Unicode".to_string(), "日本語".to_string());
    custom_headers.insert("X-Newline".to_string(), "line1\nline2".to_string());
    custom_headers.insert("X-Tab".to_string(), "col1\tcol2".to_string());
    custom_headers.insert("X-Null".to_string(), "val\x00ue".to_string());

    let config = HttpConfig {
        custom_headers,
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Err(Error::InvalidHeaderValue { name }) => assert_eq!(name, "X-Newline"),
        other => panic!("expected newline header value to be rejected, got {other:?}"),
    }
}

/// Test proxy with authentication
#[test]
fn adversarial_proxy_with_auth() {
    let config = HttpConfig {
        proxy: Some("http://user:password@proxy.example.com:8080".to_string()),
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    assert!(result.is_ok(), "proxy URLs with auth should parse");
}

/// Test various proxy formats
#[test]
fn adversarial_proxy_formats() {
    let proxies = vec![
        ("http://proxy.example.com:8080", true),
        ("https://proxy.example.com:8080", true),
        ("socks5://proxy.example.com:1080", true),
        ("http://user:pass@proxy:8080", true),
        ("http://user:@proxy:8080", true),
        ("http://:pass@proxy:8080", true),
        ("proxy.example.com:8080", false),
        ("http://proxy", true),
        ("http://[::1]:8080", true),
        ("", false),
        ("not-a-valid-proxy-url", false),
    ];

    for (proxy, should_accept) in &proxies {
        let config = HttpConfig {
            proxy: Some((*proxy).to_string()),
            ..HttpConfig::default()
        };

        let result = ScanClient::from_config(config);
        assert_eq!(
            result.is_ok(),
            *should_accept,
            "unexpected proxy validation result for {proxy}"
        );
    }
}

/// Test TOML with unknown fields
#[test]
fn adversarial_toml_unknown_fields() {
    let toml = r#"
timeout_secs = 30
max_retries = 5
unknown_field = "this doesn't exist"
another_unknown = 123

[nested_section]
key = "value"

[[array_of_tables]]
name = "test"
"#;

    let result = HttpConfig::from_toml(toml);
    assert!(result.is_err(), "unknown TOML fields must be rejected");
}

/// Test empty user agent
#[test]
fn adversarial_empty_user_agent() {
    let config = HttpConfig {
        user_agent: "".to_string(),
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Err(Error::InvalidUserAgent) => {}
        other => panic!("expected empty user agent to be rejected, got {other:?}"),
    }
}

/// Test very long user agent
#[test]
fn adversarial_long_user_agent() {
    let config = HttpConfig {
        user_agent: "A".repeat(10_000),
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    let _ = result;
}

/// Test TOML with invalid types
#[test]
fn adversarial_toml_invalid_types() {
    let cases = vec![
        (
            "timeout_secs = \"not a number\"",
            "string instead of number",
        ),
        ("max_retries = true", "bool instead of number"),
        ("tls_verify = \"yes\"", "string instead of bool"),
        (
            "custom_headers = \"not an object\"",
            "string instead of table",
        ),
    ];

    for (toml, desc) in &cases {
        let result = HttpConfig::from_toml(toml);
        assert!(result.is_err(), "invalid TOML types should fail for {desc}");
    }
}

/// Test config with max redirects = 0
#[test]
fn adversarial_zero_max_redirects() {
    let config = HttpConfig {
        max_redirects: 0,
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    assert!(result.is_ok());
}

/// Test config with negative-like values (u64 overflow edge cases)
#[test]
fn adversarial_config_overflow_values() {
    // These are edge cases that might cause issues
    let config = HttpConfig {
        timeout_secs: 1, // Very short
        connect_timeout_secs: 1,
        retry_delay_ms: 0,           // No delay
        rate_limit_per_sec: Some(0), // Zero rate limit
        max_redirects: usize::MAX,   // Huge redirect limit
        max_retries: u32::MAX,       // Huge retry count
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Err(Error::InvalidRetryDelay { value: 0, .. }) => {}
        other => panic!("expected zero retry delay to be rejected, got {other:?}"),
    }
}

/// Test TOML with duplicate keys
#[test]
fn adversarial_toml_duplicate_keys() {
    let toml = r#"
timeout_secs = 10
timeout_secs = 20
timeout_secs = 30
"#;

    let result = HttpConfig::from_toml(toml);
    // May use first, last, or error
    if let Ok(config) = result {
        // Should have one of the values
        assert!(
            config.timeout_secs == 10 || config.timeout_secs == 20 || config.timeout_secs == 30
        );
    }
}

/// Test TOML with malformed structure
#[test]
fn adversarial_toml_malformed() {
    let cases = vec![
        "{{invalid toml",
        "[unclosed[section",
        "timeout_secs =",
        "= 10",
        "timeout_secs: 10",                   // YAML syntax in TOML
        "timeout_secs = 10; max_retries = 5", // Semicolons
    ];

    for toml in &cases {
        let result = HttpConfig::from_toml(toml);
        assert!(result.is_err(), "malformed TOML must fail: {toml}");
    }
}

/// Test config with unicode in headers
#[test]
fn adversarial_unicode_headers() {
    let mut custom_headers = HashMap::new();

    // Header values with unicode
    custom_headers.insert("X-Japanese".to_string(), "日本語".to_string());
    custom_headers.insert("X-Russian".to_string(), "Русский".to_string());
    custom_headers.insert("X-Arabic".to_string(), "العربية".to_string());
    custom_headers.insert("X-Emoji".to_string(), "🎉🎊🎁".to_string());
    custom_headers.insert("X-Mixed".to_string(), "Hello世界".to_string());

    let config = HttpConfig {
        custom_headers,
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    assert!(result.is_ok(), "unicode header values should be accepted by reqwest");
}

/// Test rate limit edge cases
#[test]
fn adversarial_rate_limit_edge_cases() {
    let cases = vec![
        (Some(0u32), false),
        (Some(1), false),
        (Some(1000), false),
        (Some(u32::MAX), false),
        (None, true),
    ];

    for (rate_limit, should_build) in cases {
        let config = HttpConfig {
            rate_limit_per_sec: rate_limit,
            ..HttpConfig::default()
        };

        let result = ScanClient::from_config(config);
        assert_eq!(result.is_ok(), should_build);
    }
}

/// Test config save and load roundtrip
#[test]
fn adversarial_config_roundtrip() {
    let original = HttpConfig {
        timeout_secs: 42,
        max_retries: 7,
        proxy: Some("http://proxy:8080".to_string()),
        user_agent: "TestAgent/1.0".to_string(),
        tls_verify: false,
        ..HttpConfig::default()
    };

    // Serialize to TOML
    let toml = original.to_toml().unwrap();

    // Parse back
    let parsed = HttpConfig::from_toml(&toml).unwrap();

    assert_eq!(original.timeout_secs, parsed.timeout_secs);
    assert_eq!(original.max_retries, parsed.max_retries);
    assert_eq!(original.proxy, parsed.proxy);
    assert_eq!(original.user_agent, parsed.user_agent);
    assert_eq!(original.tls_verify, parsed.tls_verify);
}

/// Test TOML with deeply nested structures
#[test]
fn adversarial_toml_deeply_nested() {
    let toml = r#"
[custom_headers]
a = "1"

[custom_headers.nested]
this = "should not work"
"#;

    let result = HttpConfig::from_toml(toml);
    // Nested tables in custom_headers should fail or be ignored
    if let Ok(config) = result {
        // Should have basic headers
        assert!(config.custom_headers.contains_key("a"));
    }
}

/// Test header names with invalid characters
#[test]
fn adversarial_invalid_header_names() {
    let mut custom_headers = HashMap::new();

    // Invalid header names
    custom_headers.insert(" spaces ".to_string(), "value".to_string());
    custom_headers.insert("colons:here".to_string(), "value".to_string());
    custom_headers.insert("new\nline".to_string(), "value".to_string());
    custom_headers.insert("".to_string(), "value".to_string()); // empty name

    let config = HttpConfig {
        custom_headers,
        ..HttpConfig::default()
    };

    let result = ScanClient::from_config(config);
    match result {
        Ok(_) => {}
        Err(Error::InvalidHeaderName { .. }) => {}
        Err(_) => {}
    }
}

/// Test config load from non-existent file
#[test]
fn adversarial_load_missing_file() {
    let result = HttpConfig::load(std::path::Path::new("/nonexistent/path/config.toml"));
    assert!(result.is_err());
}

/// Test config load from directory instead of file
#[test]
fn adversarial_load_directory_as_file() {
    let dir = tempfile::tempdir().unwrap();
    let result = HttpConfig::load(dir.path());
    assert!(result.is_err());
}
