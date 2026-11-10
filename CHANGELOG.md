# Changelog

## [1.4.0]

### Security
- Strengthened OIDC issuer and discovery URL validation.
- Hardened Gemini API key file handling.
- Improved Unix event socket cleanup to prevent removal of replaced sockets.

### Reliability
- Detect HTTP and Gemini response read failures and oversized response bodies.
- Clear stale active upstream state when no usable upstream remains.
- Added regression tests for security and health-state handling.

### Documentation
- Updated installation and version information.
- Clarified LucX-UI event handling.
- Removed legacy resolver references.
- Clarified rollback and data-directory removal behavior.


## [1.3.0]

- Initial tracked release: UDP/TCP DNS proxy with DoH upstreams, health monitoring, `/healthz` and `/status`, optional Gemini API mode.
