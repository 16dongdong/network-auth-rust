#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
release=""
serviceName="network-auth-rust.service"
owner="nginx:nginx"
listen="127.0.0.1:18080"
nginxConfigPath=""
publicHealthUrl=""
healthTimeoutSeconds=20
requireConfigSymlink=0

usage() {
    cat <<'USAGE'
Usage: post-cutover-final-gate.sh --public-health-url <url> [options]

Options:
  --base <path>                  Release base path. Default: /var/www/ace-network-auth
  --release <name-or-path>       Expected current Rust release. Optional but recommended.
  --service <name>               systemd service name. Default: network-auth-rust.service
  --owner <user[:group]>         Expected systemd User and Group. Default: nginx:nginx
  --listen <addr:port>           Expected Rust listen address. Default: 127.0.0.1:18080
  --nginx-config <path>          Nginx site config path for readiness.
  --public-health-url <url>      Public Rust health URL checked through Nginx. Required.
  --health-timeout <sec>         Seconds to wait for health readiness. Default: 20
  --require-config-symlink       Require current config/local.php to be a valid symlink.
  -h, --help                     Show this help.

This gate is read-only. It proves that production has already cut to Rust:
current points to the expected Rust release, systemd is active, Nginx is proxying
to Rust, and public health reports runtime=rust.
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

needValue() {
    local name="$1"
    local value="${2:-}"
    [[ -n "$value" ]] || die "$name requires a value"
    printf '%s' "$value"
}

validatePositiveInteger() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 ]] ||
        die "$label must be a positive integer"
}

assertDirectReleaseChild() {
    local path="$1"
    local releasesPath="$2"
    [[ "$(dirname "$path")" == "$releasesPath" ]] || die "release path is outside releases directory: $path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            base="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --base=*)
            base="${1#*=}"
            shift
            ;;
        --release)
            release="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --release=*)
            release="${1#*=}"
            shift
            ;;
        --service)
            serviceName="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --service=*)
            serviceName="${1#*=}"
            shift
            ;;
        --owner)
            owner="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --owner=*)
            owner="${1#*=}"
            shift
            ;;
        --listen)
            listen="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --listen=*)
            listen="${1#*=}"
            shift
            ;;
        --nginx-config)
            nginxConfigPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-config=*)
            nginxConfigPath="${1#*=}"
            shift
            ;;
        --public-health-url)
            publicHealthUrl="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --public-health-url=*)
            publicHealthUrl="${1#*=}"
            shift
            ;;
        --health-timeout)
            healthTimeoutSeconds="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --health-timeout=*)
            healthTimeoutSeconds="${1#*=}"
            shift
            ;;
        --require-config-symlink)
            requireConfigSymlink=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unsupported argument: $1"
            ;;
    esac
done

[[ -n "$publicHealthUrl" ]] || die "--public-health-url is required"
validatePositiveInteger "health timeout" "$healthTimeoutSeconds"
[[ -d "$base" ]] || die "release base not found: $base"
[[ -L "$base/current" ]] || die "current release symlink not found: $base/current"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"
if [[ -n "$nginxConfigPath" && ! -f "$nginxConfigPath" ]]; then
    die "Nginx config file not found: $nginxConfigPath"
fi

base="$(readlink -f "$base")"
releasesPath="$(readlink -f "$base/releases")"
currentPath="$(readlink -f "$base/current")"
[[ -d "$currentPath" ]] || die "current release target is invalid: $base/current"
assertDirectReleaseChild "$currentPath" "$releasesPath"

if [[ -n "$release" ]]; then
    if [[ "$release" = /* ]]; then
        expectedReleasePath="$(readlink -f "$release")"
    else
        expectedReleasePath="$(readlink -f "$releasesPath/$release")"
    fi
    [[ "$currentPath" == "$expectedReleasePath" ]] ||
        die "current release mismatch: expected=$expectedReleasePath actual=$currentPath"
fi

packageCheckScript="$currentPath/deploy/scripts/release-package-check.sh"
releaseSmokeScript="$currentPath/deploy/scripts/release-smoke.sh"
cutoverReadinessScript="$currentPath/deploy/scripts/cutover-readiness-check.sh"
for scriptPath in "$packageCheckScript" "$releaseSmokeScript" "$cutoverReadinessScript"; do
    [[ -x "$scriptPath" ]] || die "required gate script is not executable: $scriptPath"
done

packageArgs=("$packageCheckScript" --release "$currentPath")
smokeArgs=(
    "$releaseSmokeScript"
    --base "$base"
    --service "$serviceName"
    --public-health-url "$publicHealthUrl"
    --health-timeout "$healthTimeoutSeconds"
)
readinessArgs=(
    "$cutoverReadinessScript"
    --base "$base"
    --service "$serviceName"
    --owner "$owner"
    --listen "$listen"
    --expect-current-runtime rust
    --expect-nginx-mode rust
    --expect-service-state active
)
if [[ "$requireConfigSymlink" -eq 1 ]]; then
    packageArgs+=(--require-config-symlink)
    smokeArgs+=(--require-config-symlink)
fi
if [[ -n "$nginxConfigPath" ]]; then
    readinessArgs+=(--nginx-config "$nginxConfigPath")
fi

bash "${packageArgs[@]}"
bash "${smokeArgs[@]}"
bash "${readinessArgs[@]}"

printf 'POST_CUTOVER_FINAL_GATE_OK base=%s current=%s runtime=rust nginx_mode=rust service_state=active\n' "$base" "$currentPath"
