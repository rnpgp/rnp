# Distro / platform maintainers

This file lists the people who maintain rnp packaging in downstream
distributions and platforms. If you maintain rnp packaging for a
distribution or platform not listed here, please open a PR adding
yourself.

rnp is mission-critical software shipped by every major Linux
distribution and several BSDs. Before making changes that could affect
packaging (ABI breaks, dependency changes, build-system reorganisations,
release flow changes), the rnp project consults this list.

For the platforms rnp is known to work on, see
`docs/supported-platforms.adoc`.

## Linux distributions

| Distribution | Maintainer | GitHub | Package | Source |
|---|---|---|---|---|
| Fedora | Remi Collet | [@remicollet](https://github.com/remicollet) | `rnp` | [src.fedoraproject.org](https://src.fedoraproject.org/rpms/rnp/) |
| RHEL / EPEL | Remi Collet | [@remicollet](https://github.com/remicollet) | `rnp` (EPEL) / Remi's RPM repo | [src.fedoraproject.org](https://src.fedoraproject.org/rpms/rnp/) |
| Debian (OpenPGP stack) | Daniel Kahn Gillmor | [@dkg](https://github.com/dkg) | `rnp` | [tracker.debian.org](https://tracker.debian.org/pkg/rnp) |
| Ubuntu | (via Debian sync) | — | `rnp` | [launchpad.net](https://launchpad.net/ubuntu/+source/rnp) |
| openSUSE | Andreas Stieger | [@andreasstieger](https://github.com/andreasstieger) | `rnp` | [build.opensuse.org](https://build.opensuse.org/package/show/security:crypto/rnp) |
| Alpine Linux | Jakub Jirutka | [@jirutka](https://github.com/jirutka) | `rnp` | [pkgs.alpinelinux.org](https://pkgs.alpinelinux.org/package/edge/community/x86_64/rnp) |
| Arch Linux | (placeholder — please PR to add) | | `rnp` | [archlinux.org](https://archlinux.org/packages/?q=rnp) |
| Gentoo | Nicholas Vinson | [@nvinson](https://github.com/nvinson) | `dev-libs/rnp` | [packages.gentoo.org](https://packages.gentoo.org/packages/dev-libs/rnp) |
| NixOS / Nix | Jeffrey Lau | [@ribose-jeffreylau](https://github.com/ribose-jeffreylau) | `rnp` (flake) | [github.com/rnpgp/rnp](https://github.com/rnpgp/rnp) (`flake.nix`) |

## BSD / other Unix

| Platform | Maintainer | GitHub | Package |
|---|---|---|---|
| FreeBSD | (placeholder — please PR to add) | | `security/rnp` |
| NetBSD | (placeholder — please PR to add) | | `security/rnp` |
| OpenBSD | (placeholder — please PR to add) | | `security/rnp` |

## macOS

| Channel | Maintainer | GitHub | Notes |
|---|---|---|---|
| Homebrew | Ribose / rnp core | [@ronaldtse](https://github.com/ronaldtse), [@ni4](https://github.com/ni4) | `brew install rnp` |
| MacPorts | (placeholder — please PR to add) | | `security/rnp` |
| PowerPC | Sergey Fedorov | [@barracuda156](https://github.com/barracuda156) | Tracks Big Sur / Monterey-on-PowerPC |

## Windows

| Channel | Maintainer | GitHub | Notes |
|---|---|---|---|
| vcpkg | Ribose / rnp core | [@ronaldtse](https://github.com/ronaldtse) | [microsoft/vcpkg#52989](https://github.com/microsoft/vcpkg/pull/52989) |
| MSYS2 | (placeholder — please PR to add) | | mingw-w64-rnp |
| Winget | (planned — see #1405) | | |

## Other platforms / languages

| Platform | Maintainer | GitHub | Repo |
|---|---|---|---|
| Ruby bindings (ruby-rnp) | Ribose | [@ronaldtse](https://github.com/ronaldtse) | [rnpgp/ruby-rnp](https://github.com/rnpgp/ruby-rnp) |
| Python bindings (py-rnp) | Ribose | [@ronaldtse](https://github.com/ronaldtse) | [rnpgp/py-rnp](https://github.com/rnpgp/py-rnp) |
| PHP bindings (php-rnp) | Ribose | [@ronaldtse](https://github.com/ronaldtse) | [rnpgp/php-rnp](https://github.com/rnpgp/php-rnp) |
| Swift bindings (swift-rnp) | Ribose | [@ronaldtse](https://github.com/ronaldtse) | [rnpgp/swift-rnp](https://github.com/rnpgp/swift-rnp) |

## Upstream dependencies

| Dependency | Project | Maintainer | GitHub |
|---|---|---|---|
| Botan | Botan | Jack Lloyd | [@randombit](https://github.com/randombit) |
| OpenSSL | OpenSSL | OpenSSL team | [@openssl/openssl](https://github.com/openssl/openssl) |
| json-c | json-c | Michael Stack | [@json-c/json-c](https://github.com/json-c/json-c) |
| BZip2 | bzip2 | Julian Seward (historical); maintained by various distros | — |
| sexpp | Ribose | Ribose / rnp core | [@rnpgp/sexp](https://github.com/rnpgp/sexp) |

## rnp project

| Role | People | GitHub |
|---|---|---|
| Project lead | Ronald Tse | [@ronaldtse](https://github.com/ronaldtse) |
| Core maintainer | Nikolai Miasnikov | [@ni4](https://github.com/ni4) |
| CI infrastructure | Ribose | (this repo + [rnpgp/rnp-ci-containers](https://github.com/rnpgp/rnp-ci-containers)) |

## Consultation policy

For changes that may affect packaging, the rnp project will:

1. Open a tracking issue describing the change and its scope.
2. Ping the relevant maintainers from this file.
3. Allow at least **2 weeks** for response before proceeding.
4. Document any maintainer concerns raised and how they were addressed.

Maintainers are encouraged to file issues proactively when their
packaging workflow breaks or could be improved.

## Updating this file

If you maintain rnp packaging for a distribution, platform, or language
binding that isn't listed here, please open a PR adding yourself. If your
contact details change, please update your entry.
