#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
release=""
listen="127.0.0.1:18081"
serviceName="network-auth-rust.service"
owner="nginx:nginx"
nginxConfigPath=""
rollbackScriptPath=""
nginxSwitchScriptPath=""
expectedCurrentRuntime="php"
expectedNginxMode="php"
expectedServiceState="inactive"
requireConfigSymlink=0
runRollbackDryRun=0
startupTimeoutSeconds=10

usage() {
    cat <<'USAGE'
Usage: pre-cutover-final-gate.sh --release <name-or-path> [options]

Options:
  --release <name-or-path>       Target Rust release name under <base>/releases, or an absolute path.
  --base <path>                  Release base path. Default: /var/www/ace-network-auth
  --listen <addr:port>           Temporary Rust listen address for pre-switch smoke. Default: 127.0.0.1:18081
  --service <name>               systemd service name for readiness check. Default: network-auth-rust.service
  --owner <user[:group]>         Expected systemd User and Group. Default: nginx:nginx
  --nginx-config <path>          Nginx site config path for readiness and rollback dry-run.
  --rollback-script <path>       Explicit rollback-to-php-release.sh path.
  --nginx-switch-script <path>   Explicit Nginx switch script passed to rollback dry-run.
  --expect-current-runtime <rt>  Expected current runtime: php, rust, or unknown. Default: php
  --expect-nginx-mode <mode>     Expected Nginx mode: php, rust, mixed, or unknown. Default: php
  --expect-service-state <state> Expected service state: active, inactive, or missing. Default: inactive
  --require-config-symlink       Require target config/local.php to be a valid symlink.
  --rollback-dry-run             Require PHP rollback dry-run to pass.
  --startup-timeout <sec>        Seconds to wait for temporary Rust health. Default: 10
  -h, --help                     Show this help.

This gate is read-only. It does not modify current, systemd, Nginx, release
files, or production traffic. It proves that the current production release is
still PHP while the target Rust release passes package, fallback, pre-switch
HTTP, and readiness checks.
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

assertDirectReleaseChild() {
    local path="$1"
    local releasesPath="$2"
    [[ "$(dirname "$path")" == "$releasesPath" ]] || die "release path is outside releases directory: $path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            release="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --release=*)
            release="${1#*=}"
            shift
            ;;
        --base)
            base="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --base=*)
            base="${1#*=}"
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
        --nginx-config)
            nginxConfigPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-config=*)
            nginxConfigPath="${1#*=}"
            shift
            ;;
        --rollback-script)
            rollbackScriptPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --rollback-script=*)
            rollbackScriptPath="${1#*=}"
            shift
            ;;
        --nginx-switch-script)
            nginxSwitchScriptPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-switch-script=*)
            nginxSwitchScriptPath="${1#*=}"
            shift
            ;;
        --expect-current-runtime)
            expectedCurrentRuntime="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --expect-current-runtime=*)
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
        --require-config-symlink)
            requireConfigSymlink=1
            shift
            ;;
        --rollback-dry-run)
            runRollbackDryRun=1
            shift
            ;;
        --startup-timeout)
            startupTimeoutSeconds="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --startup-timeout=*)
            startupTimeoutSeconds="${1#*=}"
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

[[ -n "$release" ]] || die "--release is required"
validatePositiveInteger "startup timeout" "$startupTimeoutSeconds"
validateChoice "--expect-current-runtime" "$expectedCurrentRuntime" php rust unknown
validateChoice "--expect-nginx-mode" "$expectedNginxMode" php rust mixed unknown
validateChoice "--expect-service-state" "$expectedServiceState" active inactive missing
[[ -d "$base" ]] || die "release base not found: $base"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"

base="$(readlink -f "$base")"
releasesPath="$(readlink -f "$base/releases")"
if [[ "$release" = /* ]]; then
    releaseCandidate="$release"
else
    releaseCandidate="$releasesPath/$release"
fi
[[ -d "$releaseCandidate" ]] || die "target release not found: $releaseCandidate"
releasePath="$(readlink -f "$releaseCandidate")"
assertDirectReleaseChild "$releasePath" "$releasesPath"

packageCheckScript="$releasePath/deploy/scripts/release-package-check.sh"
phpFallbackReadinessScript="$releasePath/deploy/scripts/php-fallback-readiness-check.sh"
preSwitchSmokeScript="$releasePath/deploy/scripts/pre-switch-release-smoke.sh"
cutoverReadinessScript="$releasePath/deploy/scripts/cutover-readiness-check.sh"

for scriptPath in "$packageCheckScript" "$phpFallbackReadinessScript" "$preSwitchSmokeScript" "$cutoverReadinessScript"; do
    [[ -x "$scriptPath" ]] || die "required gate script is not executable: $scriptPath"
done
if [[ "$runRollbackDryRun" -eq 1 && -z "$nginxConfigPath" ]]; then
    die "--nginx-config is required with --rollback-dry-run"
fi
if [[ -n "$nginxConfigPath" && ! -f "$nginxConfigPath" ]]; then
    die "Nginx config file not found: $nginxConfigPath"
fi

packageArgs=("$packageCheckScript" --release "$releasePath")
phpFallbackArgs=("$phpFallbackReadinessScript" --base "$base")
preSwitchArgs=(
    "$preSwitchSmokeScript"
    --base "$base"
    --release "$releasePath"
    --listen "$listen"
    --startup-timeout "$startupTimeoutSeconds"
)
readinessArgs=(
    "$cutoverReadinessScript"
    --base "$base"
    --service "$serviceName"
    --owner "$owner"
    --expect-current-runtime "$expectedCurrentRuntime"
    --expect-nginx-mode "$expectedNginxMode"
    --expect-service-state "$expectedServiceState"
)

if [[ "$requireConfigSymlink" -eq 1 ]]; then
    packageArgs+=(--require-config-symlink)
    preSwitchArgs+=(--require-config-symlink)
fi
if [[ "$runRollbackDryRun" -eq 1 ]]; then
    phpFallbackArgs+=(--rollback-dry-run --nginx-config "$nginxConfigPath")
    if [[ -n "$rollbackScriptPath" ]]; then
        phpFallbackArgs+=(--rollback-script "$rollbackScriptPath")
    fi
    if [[ -n "$nginxSwitchScriptPath" ]]; then
        phpFallbackArgs+=(--nginx-switch-script "$nginxSwitchScriptPath")
    fi
fi
if [[ -n "$nginxConfigPath" ]]; then
    readinessArgs+=(--nginx-config "$nginxConfigPath")
fi

bash "${packageArgs[@]}"
bash "${phpFallbackArgs[@]}"
bash "${preSwitchArgs[@]}"
bash "${readinessArgs[@]}"

printf 'PRE_CUTOVER_FINAL_GATE_OK base=%s release=%s current_runtime=%s target_runtime=rust nginx_mode=%s service_state=%s\n' \
    "$base" "$releasePath" "$expectedCurrentRuntime" "$expectedNginxMode" "$expectedServiceState"
