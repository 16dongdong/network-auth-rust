#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
serviceName="network-auth-rust"
listenAddress="127.0.0.1:18080"
owner="nginx:nginx"
expectedNginxMode="any"
expectedServiceState="any"
expectedCurrentRuntime="any"
nginxConfigPath=""
failures=()

usage() {
    cat <<'USAGE'
Usage: cutover-readiness-check.sh [options]

Options:
  --base <path>                  Release base path. Default: /var/www/ace-network-auth
  --service <name>               systemd service name. Default: network-auth-rust
  --listen <addr:port>           Expected Rust listen address. Default: 127.0.0.1:18080
  --owner <user[:group]>         Expected systemd User and Group. Default: nginx:nginx
  --nginx-config <path>          Optional Nginx site config file to inspect instead of full nginx -T.
  --expect-current-runtime <rt>  any, php, rust, or unknown. Default: any
  --expect-runtime <rt>          Alias for --expect-current-runtime.
  --expect-nginx-mode <mode>     any, php, rust, mixed, or unknown. Default: any
  --expect-service-state <state> any, active, inactive, or missing. Default: any
  -h, --help                     Show this help.

This script is read-only. It does not install units, reload Nginx, change current,
start services, or edit release files.
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

addFailure() {
    failures+=("$*")
    printf 'READINESS_FAIL %s\n' "$*" >&2
}

validateChoice() {
    local label="$1"
    local value="$2"
    shift 2
    local allowedValues="$*"
    local allowed
    for allowed in "$@"; do
        [[ "$value" == "$allowed" ]] && return 0
    done
    die "$label must be one of: $allowedValues"
}

requireUnitLine() {
    local unitFile="$1"
    local expectedLine="$2"
    local label="$3"
    if ! grep -Fxq "$expectedLine" "$unitFile"; then
        addFailure "systemd unit missing $label: $expectedLine"
    fi
}

requireUnitContains() {
    local unitFile="$1"
    local expectedText="$2"
    local label="$3"
    if ! grep -Fq -- "$expectedText" "$unitFile"; then
        addFailure "systemd unit missing $label: $expectedText"
    fi
}

splitOwner() {
    local ownerValue="$1"
    runtimeUser="${ownerValue%%:*}"
    runtimeGroup="${ownerValue#*:}"
    if [[ "$runtimeGroup" == "$ownerValue" ]]; then
        runtimeGroup="$runtimeUser"
    fi
    [[ -n "$runtimeUser" && -n "$runtimeGroup" ]] || die "owner must be user or user:group"
}

detectCurrentRuntime() {
    local currentPath="$1"
    if [[ -x "$currentPath/network-auth-rust" ]]; then
        printf 'rust'
        return
    fi
    if [[ -f "$currentPath/index.php" ]]; then
        printf 'php'
        return
    fi
    printf 'unknown'
}

detectServiceState() {
    if ! command -v systemctl >/dev/null 2>&1; then
        addFailure "systemctl command is not available"
        printf 'missing'
        return
    fi
    if ! systemctl cat "$serviceName" >/dev/null 2>&1; then
        printf 'missing'
        return
    fi
    if systemctl is-active --quiet "$serviceName"; then
        printf 'active'
        return
    fi
    printf 'inactive'
}

detectListenState() {
    local listenPort="${listenAddress##*:}"
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -Eq "[.:]$listenPort[[:space:]]"; then
        printf 'listening'
        return
    fi
    printf 'not-listening'
}

detectNginxMode() {
    local nginxDumpFile="$1"
    local proxyPattern="proxy_pass http://$listenAddress"
    local hasRustProxy=0
    local hasFastcgi=0

    if ! command -v nginx >/dev/null 2>&1; then
        addFailure "nginx command is not available"
        printf 'unknown'
        return
    fi
    if [[ -n "$nginxConfigPath" ]]; then
        if [[ ! -f "$nginxConfigPath" ]]; then
            addFailure "nginx config file not found: $nginxConfigPath"
            printf 'unknown'
            return
        fi
        cp "$nginxConfigPath" "$nginxDumpFile"
    else
        if ! nginx -T >"$nginxDumpFile" 2>/dev/null; then
            addFailure "nginx -T failed"
            printf 'unknown'
            return
        fi
    fi
    if grep -Fq "$proxyPattern" "$nginxDumpFile"; then
        hasRustProxy=1
    fi
    if grep -Eq '^[[:space:]]*fastcgi_pass[[:space:]]+' "$nginxDumpFile"; then
        hasFastcgi=1
    fi
    if [[ "$hasRustProxy" -eq 1 && "$hasFastcgi" -eq 1 ]]; then
        printf 'mixed'
        return
    fi
    if [[ "$hasRustProxy" -eq 1 ]]; then
        printf 'rust'
        return
    fi
    if [[ "$hasFastcgi" -eq 1 ]]; then
        printf 'php'
        return
    fi
    printf 'unknown'
}

checkSystemdUnit() {
    local unitFile="$1"
    local runtimeUser="$2"
    local runtimeGroup="$3"

    if [[ "$serviceState" == "missing" ]]; then
        if [[ "$expectedServiceState" == "missing" ]]; then
            return
        fi
        addFailure "systemd service is not installed: $serviceName"
        return
    fi

    systemctl cat "$serviceName" >"$unitFile"
    requireUnitLine "$unitFile" "WorkingDirectory=$base/current" "WorkingDirectory"
    requireUnitLine "$unitFile" "User=$runtimeUser" "User"
    requireUnitLine "$unitFile" "Group=$runtimeGroup" "Group"
    requireUnitContains "$unitFile" "ExecStart=$base/current/network-auth-rust serve" "ExecStart binary"
    requireUnitContains "$unitFile" "--listen $listenAddress" "listen address"
    requireUnitContains "$unitFile" "--config $base/current/config/local.php" "config path"
    requireUnitContains "$unitFile" "--public-root $base/current/public" "public root"
    requireUnitContains "$unitFile" "--schema $base/current/resources/install/schema.sql" "schema path"
    requireUnitContains "$unitFile" "--install-lock $base/shared/storage/cache/install.lock" "install lock"
}

checkExpectedState() {
    if [[ "$expectedCurrentRuntime" != "any" && "$currentRuntime" != "$expectedCurrentRuntime" ]]; then
        addFailure "current runtime mismatch: expected=$expectedCurrentRuntime actual=$currentRuntime"
    fi
    if [[ "$expectedNginxMode" != "any" && "$nginxMode" != "$expectedNginxMode" ]]; then
        addFailure "nginx mode mismatch: expected=$expectedNginxMode actual=$nginxMode"
    fi
    if [[ "$expectedServiceState" != "any" && "$serviceState" != "$expectedServiceState" ]]; then
        addFailure "service state mismatch: expected=$expectedServiceState actual=$serviceState"
    fi
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
        --service)
            serviceName="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --service=*)
            serviceName="${1#*=}"
            shift
            ;;
        --listen)
            listenAddress="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --listen=*)
            listenAddress="${1#*=}"
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
        --nginx-config)
            nginxConfigPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-config=*)
            nginxConfigPath="${1#*=}"
            shift
            ;;
        --expect-current-runtime|--expect-runtime)
            expectedCurrentRuntime="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --expect-current-runtime=*|--expect-runtime=*)
            expectedCurrentRuntime="${1#*=}"
            shift
            ;;
        --expect-nginx-mode)
            expectedNginxMode="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --expect-nginx-mode=*)
            expectedNginxMode="${1#*=}"
            shift
            ;;
        --expect-service-state)
            expectedServiceState="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --expect-service-state=*)
            expectedServiceState="${1#*=}"
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

validateChoice "--expect-current-runtime" "$expectedCurrentRuntime" any php rust unknown
validateChoice "--expect-nginx-mode" "$expectedNginxMode" any php rust mixed unknown
validateChoice "--expect-service-state" "$expectedServiceState" any active inactive missing
splitOwner "$owner"
[[ -d "$base" ]] || die "release base not found: $base"
[[ -L "$base/current" || -d "$base/current" ]] || die "current path not found: $base/current"

base="$(readlink -f "$base")"
currentPath="$(readlink -f "$base/current")"
currentRuntime="$(detectCurrentRuntime "$currentPath")"
serviceState="$(detectServiceState)"
listenState="$(detectListenState)"
scratch="$(mktemp -d)"
cleanup() {
    rm -rf "$scratch"
}
trap cleanup EXIT

nginxMode="$(detectNginxMode "$scratch/nginx.conf")"
checkSystemdUnit "$scratch/systemd-unit.txt" "$runtimeUser" "$runtimeGroup"
checkExpectedState

printf 'CUTOVER_READINESS_STATUS base=%s current=%s current_runtime=%s service=%s service_state=%s listen=%s listen_state=%s nginx_mode=%s\n' \
    "$base" "$currentPath" "$currentRuntime" "$serviceName" "$serviceState" "$listenAddress" "$listenState" "$nginxMode"

if [[ "${#failures[@]}" -gt 0 ]]; then
    printf 'CUTOVER_READINESS_FAILED failures=%s\n' "${#failures[@]}" >&2
    exit 1
fi

printf 'CUTOVER_READINESS_OK base=%s service=%s nginx_mode=%s\n' "$base" "$serviceName" "$nginxMode"
