//! Basic scanclient usage example — make an HTTP request with security defaults.
//!
//! Run: cargo run --example basic

use scanclient::{HttpConfig, ScanClient};

#[tokio::main]
async fn main() -> scanclient::Result<()> {
    let config = HttpConfig::from_toml(
        r#"
        timeout_secs = 10
        max_retries = 2
        follow_redirects = true
        [custom_headers]
        User-Agent = "scanclient/0.1"
    "#,
    )
    .unwrap();

    let client = ScanClient::from_config(config)?;

    // Make a real request
    let response = client.get("https://example.com").await?;

    println!("status: {}", response.status());
    println!("headers: {} total", response.headers().len());
    println!("body: {} bytes", response.body_bytes().len());

    Ok(())
}
