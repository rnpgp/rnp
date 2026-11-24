# ci/build_prebuilt.ps1
#
# Windows MSVC counterpart to ci/build_prebuilt.sh. Uses vcpkg to obtain
# a static dependency stack (bzip2, zlib, botan or openssl) and
# builds librnp as a static library against it, then stages everything
# into a release-ready tarball with the same layout as the Linux/macOS
# builds produced by build_prebuilt.sh.
#
# Usage:
#   ci/build_prebuilt.ps1 -Backend <botan|openssl> -Version < vX.Y.Z > [-WorkDir <path>]
#
# Requires:
#   * Visual Studio 2022 (MSVC) — `windows-latest` runner has it.
#   * CMake 3.18+.
#   * vcpkg, either at $env:VCPKG_ROOT or C:\vcpkg. The script will
#     bootstrap it if missing.
#
# Output:
#   $env:RNP_ARTIFACT_DIR\rnp-<version>-x86_64-pc-windows-msvc-<backend>.tar.gz
#   $env:RNP_ARTIFACT_DIR\rnp-<version>-x86_64-pc-windows-msvc-<backend>.sha256
#
# Notes:
#   * Uses the x64-windows-static vcpkg triplet — every dep is compiled
#     with /MT (static MSVC runtime). Consumers linking the resulting
#     .lib files must also use /MT.
#   * The botan port in vcpkg enables a different module set than the
#     ci/botan3-*-modules files used by build_prebuilt.sh. rnp's CMake
#     feature detection should fail loudly if any required module is
#     missing; bump vcpkg or override the botan feature flags in vcpkg
#     if so.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('botan', 'openssl')]
    [string]$Backend,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$WorkDir = "$PWD\prebuilt-work"
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RnpSrc    = (Resolve-Path "$ScriptDir\..").Path
$ArtifactDir = if ($env:RNP_ARTIFACT_DIR) { $env:RNP_ARTIFACT_DIR } else { Join-Path $WorkDir 'artifacts' }

$Target = 'x86_64-pc-windows-msvc'

New-Item -ItemType Directory -Force -Path $WorkDir, $ArtifactDir | Out-Null
$Prefix = Join-Path $WorkDir 'prefix'
if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

# Locate vcpkg. Use the preinstalled C:\vcpkg on windows-latest.
$VcpkgDir = 'C:\vcpkg'
if (-not (Test-Path "$VcpkgDir\vcpkg.exe")) {
    $VcpkgDir = $env:VCPKG_ROOT
}
if (-not $VcpkgDir -or -not (Test-Path "$VcpkgDir\vcpkg.exe")) {
    throw "vcpkg not found at C:\vcpkg or VCPKG_ROOT=$VcpkgDir"
}
$Triplet = 'x64-windows-static'

# Install the dependency stack via vcpkg classic mode. Run from a
# temp dir so no vcpkg.json from the repo root interferes with
# classic-mode detection. This is the same pattern rnp's own
# windows-native.yml CI uses successfully.
$Packages = @('bzip2', 'zlib', 'getopt', 'dirent')
if ($Backend -eq 'botan') {
    $Packages += 'botan'
} else {
    $Packages += 'openssl'
}
$VcpkgWorkDir = "$WorkDir\vcpkg-work"
New-Item -ItemType Directory -Force -Path $VcpkgWorkDir | Out-Null
Push-Location $VcpkgWorkDir
try {
    Write-Host "=== vcpkg install ($Triplet): $Packages ==="
    & "$VcpkgDir\vcpkg.exe" install --triplet $Triplet $Packages
    if ($LASTEXITCODE -ne 0) { throw "vcpkg install failed" }
} finally {
    Pop-Location
}

# vcpkg classic mode installs into <vcpkg-root>\installed\<triplet>\.
$VcpkgInstall = Join-Path $VcpkgDir "installed\$Triplet"
Write-Host "=== staging vcpkg install into $Prefix ==="
Copy-Item -Recurse -Force "$VcpkgInstall\*" "$Prefix\"

# Build rnp against the prefix. Pass --no-default-features via the
# ENABLE_* flags we care about; PQC is enabled on the botan backend
# to match the Linux/macOS script.
$RnpBuild = Join-Path $WorkDir 'rnp-build'
if (Test-Path $RnpBuild) { Remove-Item -Recurse -Force $RnpBuild }
New-Item -ItemType Directory -Force -Path $RnpBuild | Out-Null
Push-Location $RnpBuild
try {
    # Use the Ninja generator (preinstalled on windows-latest). Ninja
    # doesn't need VS-detection probes that fail when the MSVC env
    # isn't fully propagated to cmake. The MSVC compiler is found via
    # the toolchain set up by ilammy/msvc-dev-cmd.
    Write-Host "Using CMake generator: Ninja"

    $cmakeArgs = @(
        '-G', 'Ninja',
        "-DCMAKE_INSTALL_PREFIX=$Prefix",
        '-DCMAKE_BUILD_TYPE=Release',
        '-DBUILD_SHARED_LIBS=OFF',
        '-DBUILD_TESTING=OFF',
        "-DCRYPTO_BACKEND=$Backend",
        "-DCMAKE_PREFIX_PATH=$Prefix",
        "-DCMAKE_TOOLCHAIN_FILE=$VcpkgDir\scripts\buildsystems\vcpkg.cmake",
        "-DVCPKG_TARGET_TRIPLET=$Triplet",
        # vcpkg's x64-windows-static triplet compiles every dep with
        # /MT (static MSVC runtime). Match it on the rnp build so the
        # .lib files link cleanly -- Botan's allocator (and any other
        # dep that touches runtime internals directly) otherwise
        # triggers LNK2038 runtime-library mismatch.
        '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded'
    )
    if ($Backend -eq 'botan') {
        $cmakeArgs += '-DENABLE_PQC=ON'
    }
    Write-Host "=== rnp $Version (backend: $Backend) ==="
    & cmake $RnpSrc @cmakeArgs
    if ($LASTEXITCODE -ne 0) { throw "rnp cmake configure failed" }
    & cmake --build . --config Release --parallel
    if ($LASTEXITCODE -ne 0) { throw "rnp build failed" }
    & cmake --install . --config Release
    if ($LASTEXITCODE -ne 0) { throw "rnp install failed" }
} finally {
    Pop-Location
}

# Stage into the release-ready tarball layout.
$TarballName = "rnp-$Version-$Target-$Backend"
$Staging = Join-Path $WorkDir $TarballName
if (Test-Path $Staging) { Remove-Item -Recurse -Force $Staging }
New-Item -ItemType Directory -Force -Path $Staging, (Join-Path $Staging 'include'), (Join-Path $Staging 'lib') | Out-Null

# Headers
Copy-Item -Recurse -Force (Join-Path $Prefix 'include\*') (Join-Path $Staging 'include\')

# Static archives (.lib on MSVC)
$LibSrc = Join-Path $Prefix 'lib'
Get-ChildItem -Path $LibSrc -Filter '*.lib' -ErrorAction SilentlyContinue |
    Copy-Item -Destination (Join-Path $Staging 'lib')
Get-ChildItem -Path $LibSrc -Filter '*.a' -ErrorAction SilentlyContinue |
    Copy-Item -Destination (Join-Path $Staging 'lib')

# CMake config + pkg-config so downstream find_package(rnp) and pkg-config
# --libs rnp both work.
if (Test-Path (Join-Path $LibSrc 'cmake')) {
    Copy-Item -Recurse -Force (Join-Path $LibSrc 'cmake') (Join-Path $Staging 'lib\')
}
if (Test-Path (Join-Path $LibSrc 'pkgconfig')) {
    Copy-Item -Recurse -Force (Join-Path $LibSrc 'pkgconfig') (Join-Path $Staging 'lib\')
}

# Emit per-component vcpkg.json manifests under share\rnp\components\<name>\
# so syft's default vcpkg-manifest-cataloger captures component identities,
# versions, and SPDX licenses in both SPDX 3.0 and CycloneDX 1.7 SBOMs.
function Write-SbomManifest {
    param(
        [string]$Name,
        [string]$ComponentVersion,
        [string]$License,
        [string]$Homepage
    )
    $dir = Join-Path $Staging "share\rnp\components\$Name"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $json = @"
{
  "name": "$Name",
  "version-string": "$ComponentVersion",
  "license": "$License",
  "homepage": "$Homepage"
}
"@
    Set-Content -Path (Join-Path $dir 'vcpkg.json') -Value $json -Encoding utf8
}

$vcpkgVersions = @{}
& "$VcpkgDir\vcpkg.exe" list --triplet $Triplet | ForEach-Object {
    if ($_ -match '^([a-zA-Z0-9_-]+):[^\s]+\s+([^\s#]+)') {
        $vcpkgVersions[$Matches[1]] = $Matches[2]
    }
}

$rnpVer = $Version -replace '^v', ''
$sexppVer = '0.9.0'
$sexppVerFile = Join-Path $RnpSrc 'src\libsexpp\version.txt'
if (Test-Path $sexppVerFile) {
    $sexppVer = (Get-Content -Raw $sexppVerFile).Trim()
}
$nlohmannVer = '3.11.3'
$nlohmannHeader = Join-Path $RnpSrc 'src\lib\nlohmann\nlohmann\json.hpp'
if (Test-Path $nlohmannHeader) {
    $verLine = Select-String -Path $nlohmannHeader -Pattern 'version (\d+\.\d+\.\d+)' | Select-Object -First 1
    if ($verLine) { $nlohmannVer = $verLine.Matches[0].Groups[1].Value }
}
$prebuiltVersionsFile = Join-Path $ScriptDir 'prebuilt-versions.env'
$sha1cdMatch = Select-String -Path $prebuiltVersionsFile -Pattern '^SHA1CD_VERSION=(.+)$' | Select-Object -First 1
if (-not $sha1cdMatch) {
    throw "SHA1CD_VERSION missing in $prebuiltVersionsFile"
}
$sha1cdVer = $sha1cdMatch.Matches[0].Groups[1].Value.Trim()

Write-SbomManifest -Name 'rnp' -ComponentVersion $rnpVer -License 'BSD-2-Clause AND Apache-2.0 AND BSD-3-Clause AND MIT' -Homepage 'https://github.com/rnpgp/rnp'
Write-SbomManifest -Name 'sexpp' -ComponentVersion $sexppVer -License 'MIT' -Homepage 'https://github.com/rnpgp/sexpp'
Write-SbomManifest -Name 'nlohmann-json' -ComponentVersion $nlohmannVer -License 'MIT' -Homepage 'https://github.com/nlohmann/json'
Write-SbomManifest -Name 'sha1collisiondetection' -ComponentVersion $sha1cdVer -License 'MIT' -Homepage 'https://github.com/cr-marcstevens/sha1collisiondetection'
Write-SbomManifest -Name 'zlib' -ComponentVersion ($vcpkgVersions['zlib'] ?? '1.3.1') -License 'Zlib' -Homepage 'https://zlib.net'
Write-SbomManifest -Name 'bzip2' -ComponentVersion ($vcpkgVersions['bzip2'] ?? '1.0.8') -License 'bzip2-1.0.6' -Homepage 'https://sourceware.org/bzip2/'
if ($Backend -eq 'botan') {
    Write-SbomManifest -Name 'botan' -ComponentVersion ($vcpkgVersions['botan'] ?? '3.12.0') -License 'BSD-2-Clause' -Homepage 'https://botan.randombit.net'
} else {
    Write-SbomManifest -Name 'openssl' -ComponentVersion ($vcpkgVersions['openssl'] ?? '3.6.0') -License 'Apache-2.0' -Homepage 'https://www.openssl.org'
}

# MANIFEST.txt — same shape as the Linux/macOS one.
$linkLibs = if ($Backend -eq 'botan') {
    'rnp.lib sexpp.lib botan-3.lib zlib.lib libbz2.lib'
} else {
    'rnp.lib sexpp.lib libcrypto.lib libssl.lib zlib.lib libbz2.lib'
}
$manifest = @"
rnp $Version -- prebuilt static library bundle (Windows MSVC)

Target:     $Target
Backend:    $Backend

Contents
--------
  include\rnp\      public FFI headers (rnp.h, rnp_err.h, rnp_export.h, rnp_ver.h)
  include\botan-3\  (botan backend) or include\openssl\ (openssl backend)
  include\bzlib.h   bzip2 header
  include\zlib.h    zlib header
  lib\rnp.lib       librnp static library
  lib\sexpp.lib     sexpp static library (librnp depends on this; headers
                    not included -- not needed by C API consumers)
  lib\botan-3.lib   (botan backend) or libcrypto.lib + libssl.lib (openssl)
  lib\zlib.lib      zlib static library
  lib\libbz2.lib    bzip2 static library
  lib\cmake\rnp\    CMake config (find_package(rnp))
  lib\pkgconfig\    pkg-config files

Linking (MSVC)
--------------
Add include\ to your compiler's header search path, add lib\ to your
linker's library search path, then link against (in order):
  $linkLibs

The static MSVC runtime (/MT) is used by every dep in this bundle. The
consumer must also compile with /MT.

Source
------
Produced by ci/build_prebuilt.ps1 in the rnp repository
(https://github.com/rnpgp/rnp).
"@
Set-Content -Path (Join-Path $Staging 'MANIFEST.txt') -Value $manifest -Encoding utf8

# Tarball. The Windows tar.exe bundled with Git for Windows + Visual
# Studio supports -czf and the standard options. Tarball-level metadata
# normalization is the same trade-off as on Linux/macOS: out of scope
# for v1 (see build_prebuilt.sh comment for details).
$Tarball = Join-Path $ArtifactDir "$TarballName.tar.gz"
Write-Host "=== packaging ==="
# Use Windows native tar.exe (C:\Windows\System32\tar.exe, preinstalled
# on Windows 10 1803+ and Windows Server 2019+). The MSYS2 tar from
# Git for Windows that comes first in PATH can't write to Windows-
# style paths like D:\...; it expects POSIX /d/... and the path
# conversion is unreliable. Native tar handles both path styles.
$WinTar = Join-Path $env:WINDIR 'System32\tar.exe'
if (-not (Test-Path $WinTar)) {
    throw "Windows native tar.exe not found at $WinTar"
}
Push-Location $WorkDir
try {
    & $WinTar -czf $Tarball $TarballName
    if ($LASTEXITCODE -ne 0) { throw "tar failed" }
} finally {
    Pop-Location
}

# Sha256 in the same "hash  filename" format as the Linux/macOS sidecar.
$hash = (Get-FileHash -Path $Tarball -Algorithm SHA256).Hash.ToLower()
"$hash  $TarballName.tar.gz" |
    Set-Content -Path (Join-Path $ArtifactDir "$TarballName.sha256") -Encoding ascii

# GPG detached signature if a key is configured. Most Windows runners
# ship gpg via Git for Windows; if absent, this step is skipped.
if ($env:RNP_GPG_KEY_ID) {
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if ($gpg) {
        Write-Host "Signing $Tarball with key $env:RNP_GPG_KEY_ID"
        & $gpg.Source --batch --yes --detach-sign --armor `
            --local-user $env:RNP_GPG_KEY_ID `
            --output (Join-Path $ArtifactDir "$TarballName.tar.gz.asc") `
            $Tarball
    } else {
        Write-Host 'gpg not found in PATH; skipping GPG signature.'
    }
} else {
    Write-Host 'RNP_GPG_KEY_ID not set; skipping GPG signature.'
}

Write-Host ""
Write-Host "=== Built: $Tarball ==="
Get-Item $Tarball | Format-List Name, Length
