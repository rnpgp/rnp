# Support Policy

This document declares the supported release streams, support end dates, security vulnerability reporting channels, and end-of-life and backport policies for `rnpgp/rnp` in accordance with EU Cyber Resilience Act (CRA) Article 14.

## Supported release streams

Each `rnpgp/rnp` release stream is supported for two years from the release date of its latest release unless a different date is explicitly declared. The release workflow (`.github/workflows/release.yml`) computes this default `support-until` date (`+2 years` in `YYYY-MM-DD` format, overridable via the `support_until` workflow input) and stamps it into the release's `lifecycle.json` asset and GitHub Release notes.

| Release stream | Latest version | Release date | Support status | Support until |
|---|---|---|---|---|
| `0.18.x` | `v0.18.1` | `2025-11-21` | Supported | `2027-11-21` |
| `0.17.x` | `v0.17.1` | `2024-05-14` | End of life | `2026-05-14` |
| `0.16.x` and earlier | `v0.16.3` | `2023-04-13` | End of life | `2025-04-13` |

Version `v0.18.0` was retracted due to `CVE-2025-13470` (`RA-2025-11-20`) and is not supported. All users on the `0.18.x` stream must run `v0.18.1` or later.

## Security vulnerability reporting

Do not open a public GitHub issue for security vulnerabilities. Report suspected security vulnerabilities privately using one of the following channels (also documented in [`SECURITY.md`](SECURITY.md)):

- Submit a private vulnerability report through the GitHub Security tab at <https://github.com/rnpgp/rnp/security/advisories/new>.
- Email the `rnpgp/rnp` maintainers at `security@rnpgp.org`.
- Submit a report through the Ribose Security Feedback form at <https://www.ribose.com/security/feedback>.

Ribose operates as a CVE Numbering Authority (CNA) and publishes security advisories and machine-readable vulnerability feeds at <https://cve.ribose.com>. The authoritative per-package vulnerability feeds for `rnpgp/rnp` (`pkg:github/rnpgp/rnp`) are published at:

- The OSV feed for `rnpgp/rnp` is published at <https://cve.ribose.com/feeds/osv/rnp.json>.
- The GHSA feed for `rnpgp/rnp` is published at <https://cve.ribose.com/feeds/ghsa/rnp.json>.

Machine-readable CSAF and VEX feeds for `rnpgp/rnp` are planned at <https://cve.ribose.com> as part of the release provenance program. For FIPS-mode certification boundaries and algorithm security profiles, refer to [`docs/security.adoc`](docs/security.adoc).

## End-of-life and backport policy

1. Active release streams receive security fixes and critical bug fixes until their declared `support-until` date.
2. Security fixes are released as patch versions on the active supported release stream when immediate remediation is required.
3. New features, non-critical bug fixes, and refactoring changes are developed on `main` for the next release stream and are not backported to prior release streams.
4. When a release stream passes its `support-until` date, it reaches end of life and receives no further security updates, bug fixes, or backports.
5. Users and downstream distribution maintainers (listed in [`MAINTAINERS.md`](MAINTAINERS.md)) must upgrade to an active supported release stream before their current stream reaches its `support-until` date.

## General support and bug reports

Non-security bug reports, build issues, and feature requests are tracked in the public GitHub issue tracker at <https://github.com/rnpgp/rnp/issues>.
