# Changelog

## [Unreleased]

### DNS
- Add optional exact-hostname `local_hosts` overrides for A/AAAA, with 60-second TTL and DNSSEC AD cleared.
- Return NOERROR/NODATA for missing address families and suppress HTTPS/SVCB records for configured hosts.
- Keep empty `local_hosts` behavior identical to the normal DoH path.

## [1.6.0] - 2026-11-10

### Added
- Optional `local_hosts` overrides for exact DNS hostnames.
- Local A/AAAA answers with 60-second TTL, NOERROR/NODATA for missing address families, and AD cleared.
- Empty HTTPS/SVCB answers for configured local hostnames.
- Russian documentation with configuration examples, address selection guidance, hot reload, and `dig` verification steps.




## [1.5.0]

### Reliability
- Resolve DoH endpoint A/AAAA records automatically through independent bootstrap DNS resolvers.
- Benchmark all resolved DoH IPs concurrently using a real DoH query and pin traffic to the fastest responsive address.
- Refresh bootstrap addresses every six hours and after connection failures, retaining the last working IP list during temporary DNS failures.
- Keep TLS hostname verification and SNI while dialing resolved IP addresses.
- Preserve legacy bootstrap_ips as optional fallback addresses.

### Packaging
- Exclude README.md and examples/ from release ZIPs; keep them in the source repository.

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
