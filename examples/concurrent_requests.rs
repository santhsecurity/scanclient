//! Example demonstrating concurrent requests.
//!
//! Run: cargo run --example concurrent_requests

use scanclient::{HttpConfig, ScanClient};

#[tokio::main]
async fn main() -> scanclient::Result<()> {
    let config = HttpConfig::from_toml("timeout_secs = 5").unwrap();
    let client = ScanClient::from_config(config)?;

    let urls = vec!["https://example.com", "https://httpbin.org/get"];

    for url in urls {
        match client.get(url).await {
            Ok(resp) => println!("{} -> status {}", url, resp.status()),
            Err(e) => println!("{} -> error {}", url, e),
        }
    }

    Ok(())
}
