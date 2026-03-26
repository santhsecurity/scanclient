//! Example demonstrating custom timeout configuration.
//!
//! Run: cargo run --example custom_timeout

use scanclient::{HttpConfig, ScanClient};

#[tokio::main]
async fn main() -> scanclient::Result<()> {
    // Setting a very short timeout to intentionally cause a timeout error
    let config = HttpConfig::from_toml(
        r#"
        timeout_secs = 1
        max_retries = 0
        "#,
    )
    .unwrap();

    let client = ScanClient::from_config(config)?;

    match client.get("https://example.com").await {
        Ok(resp) => println!("Got response: status {}", resp.status()),
        Err(e) => println!("Request failed as expected: {}", e),
    }

    Ok(())
}
