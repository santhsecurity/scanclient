//! # scanclient
//!
//! High-performance, connection-pooled, and observable HTTP client designed specifically
//! for Santh security scanning tools.
//!
//! This crate wraps `reqwest` to provide unified rate-limiting, custom DNS resolution,
//! automatic retries on specific status codes, proxy rotation, and specific security
//! scanning configurations (e.g. ignoring TLS errors or setting specific User-Agents).
//!
//! ## Architecture
//! - [`ScanClient`]: The main orchestration client.
//! - [`HttpConfig`]: Configuration options for proxies, timeouts, and rate limits.
//! - [`ScanResponse`]: A tailored response object capturing timing and status.
//!
//! ## Quick Start
//!
//! ```rust
//! use scanclient::config::HttpConfig;
//!
//! let config = HttpConfig::default();
//! assert_eq!(config.timeout_secs, 10);
//! assert_eq!(config.max_retries, 3);
//! assert!(config.tls_verify);
//!
//! // Load from TOML
//! let custom = HttpConfig::from_toml("timeout_secs = 30").unwrap();
//! assert_eq!(custom.timeout_secs, 30);
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::needless_pass_by_value)]

pub mod client;
/// TOML configuration helpers.
pub mod config;
/// HTTP response wrappers.
pub mod response;

pub use client::{Error, Result, ScanClient};
pub use config::{HttpConfig, HttpConfigError};
pub use response::ScanResponse;

#[cfg(test)]
mod adversarial_tests;
