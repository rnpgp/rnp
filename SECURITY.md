# Security policy

This document describes how to report security vulnerabilities in `rnpgp/rnp` and which vulnerability feeds are published for the project. The supported release streams and their support end dates are declared in [SUPPORT.md](SUPPORT.md).

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities. Report suspected security vulnerabilities privately through either of the following channels.

- Use the GitHub private vulnerability reporting button on this repository, which is enabled under the Security tab.
- Send an email to the maintainers at security@rnpgp.org.

A report may also be submitted through the Ribose Security Feedback form at <https://www.ribose.com/security/feedback>.

## Advisories and vulnerability feeds

Ribose operates as a CVE Numbering Authority (CNA) and publishes security advisories at <https://cve.ribose.com>. The authoritative machine-readable vulnerability feeds for `rnpgp/rnp` (package `pkg:github/rnpgp/rnp`) are published at the following addresses.

- The OSV feed is published at <https://cve.ribose.com/feeds/osv/rnp.json>.
- The GHSA feed is published at <https://cve.ribose.com/feeds/ghsa/rnp.json>.

Common Security Advisory Framework (CSAF) and Vulnerability Exploitability eXchange (VEX) documents for `rnpgp/rnp` releases are planned as part of the release provenance program and will be published under the same feed structure once available.

## Supported versions and end of life

Security fixes are provided to release streams whose support period has not ended. The supported release streams, the `support-until` dates, and the end-of-life and backport policy are declared in [SUPPORT.md](SUPPORT.md). Release streams past their `support-until` date receive no security updates.

## Algorithm security profiles

For the FIPS-mode certification boundaries and the algorithm security profiles that rnp applies to signature and key validation, refer to [docs/security.adoc](docs/security.adoc).
