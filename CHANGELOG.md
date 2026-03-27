# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-26

### Added
- Comprehensive documentation for all public functions.
- Added code examples for key functions in doc comments.

## [0.1.0] - 2026-03-XX

### Added
- Initial release of `scanclient`.
- `ScanClient` - high-performance HTTP client for security scanning.
- `HttpConfig` - configuration with TOML file support.
- `ScanResponse` - tailored response object with timing and status.
- Automatic retries with exponential backoff.
- Rate limiting support.
- Proxy support (HTTP, HTTPS, SOCKS5).
- Custom headers and User-Agent.
- TLS configuration options (verify, accept invalid certs/hostnames).
- Builder pattern for `HttpConfig`.
