#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
release=""
serviceName="network-auth-rust"
nginxConfigPath=""
nginxBackupPath=""
nginxSwitchScriptOverride=""
phpHealthUrl=""
phpHealthTimeout=10
apply=0
stopService=1
storageDirs=(cache logs runtime-cache build cloud-storage)

usage() {
    cat <<'USAGE'
Usage: rollback-to-php-release.sh --release <name-or-path> --nginx-config <path> [options]

Options:
  --release <name-or-path>  Target PHP release name under <base>/releases, or an absolute release path.
  --base <path>             Release base path. Default: /var/www/ace-network-auth
  --nginx-config <path>     Nginx site config restored to PHP mode.
  --nginx-backup <path>     PHP Nginx config backup. Default: <nginx-config>.php-backup
  --nginx-switch-script <path>
                            Optional Nginx backend switch script. Default: current or target switch-nginx-backend.sh
  --service <name>          Rust systemd service stopped after Nginx is restored. Default: network-auth-rust
  --php-health-url <url>    Optional PHP public health URL checked after rollback.
  --php-health-timeout <s>  Seconds to wait for PHP health readiness. Default: 10
  --skip-service-stop       Do not stop the Rust service after rollback.
  --apply                   Actually switch current, restore Nginx, and stop Rust service.
  -h, --help                Show this help.

Default mode is dry-run. This script is for Rust -> PHP rollback only.
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

printCommand() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
}

canonicalPath() {
    readlink -f "$1"
}

assertDirectReleaseChild() {
    local path="$1"
    local releasesPath="$2"
    [[ "$(dirname "$path")" == "$releasesPath" ]] || die "release path is outside releases directory: $path"
}

assertPhpRelease() {
    local releasePath="$1"
    [[ -f "$releasePath/index.php" ]] || die "PHP release entry file not found: $releasePath/index.php"
    [[ -d "$releasePath/public" ]] || die "PHP release public directory not found: $releasePath/public"
    [[ -d "$releasePath/config" ]] || die "PHP release config directory not found: $releasePath/config"
    [[ ! -x "$releasePath/network-auth-rust" ]] || die "target release looks like Rust, not PHP: $releasePath"
}

assertReleaseStorageLinks() {
    local releasePath="$1"
    local directoryName
    local releaseStoragePath
    local releaseStorageTarget
    local sharedStorageChildPath

    for directoryName in "${storageDirs[@]}"; do
        releaseStoragePath="$releasePath/storage/$directoryName"
        sharedStorageChildPath="$(readlink -f "$sharedStoragePath/$directoryName" 2>/dev/null || true)"
        releaseStorageTarget="$(readlink -f "$releaseStoragePath" 2>/dev/null || true)"
        [[ -n "$sharedStorageChildPath" && -d "$sharedStorageChildPath" ]] || die "shared storage child not found: $base/shared/storage/$directoryName"
        [[ -n "$releaseStorageTarget" ]] || die "PHP release storage link not found: $releaseStoragePath"
        [[ "$releaseStorageTarget" == "$sharedStorageChildPath" ]] || die "PHP release storage must point to shared storage: $releaseStoragePath -> $releaseStorageTarget"
    done
}

switchCurrent() {
    local target="$1"
    local tempLink="$base/.current-rollback.$$"
    rm -f "$tempLink"
    ln -s "$target" "$tempLink"
    mv -Tf "$tempLink" "$base/current"
}

checkPhpHealth() {
    [[ -n "$phpHealthUrl" ]] || return 0
    command -v curl >/dev/null 2>&1 || die "curl is required for PHP health checks"
    local responseBody
    local headerFile
    local deadline
    deadline=$(( $(date +%s) + phpHealthTimeout ))

    while true; do
        headerFile="$(mktemp)"
        responseBody="$(curl -fsS -D "$headerFile" "$phpHealthUrl" 2>/dev/null || true)"
        if [[ -n "$responseBody" ]] &&
            grep -Eiq '^content-type:[[:space:]]*application/json([;[:space:]]|$)' "$headerFile" &&
            printf '%s' "$responseBody" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
            rm -f "$headerFile"
            return 0
        fi
        rm -f "$headerFile"

        [[ "$(date +%s)" -lt "$deadline" ]] || die "PHP health URL did not become ready: $phpHealthUrl"
        sleep 1
    done
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
        --nginx-config)
            nginxConfigPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-config=*)
            nginxConfigPath="${1#*=}"
            shift
            ;;
        --nginx-backup)
            nginxBackupPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-backup=*)
            nginxBackupPath="${1#*=}"
            shift
            ;;
        --nginx-switch-script)
            nginxSwitchScriptOverride="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --nginx-switch-script=*)
            nginxSwitchScriptOverride="${1#*=}"
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
        --php-health-url)
            phpHealthUrl="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --php-health-url=*)
            phpHealthUrl="${1#*=}"
            shift
            ;;
        --php-health-timeout)
            phpHealthTimeout="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --php-health-timeout=*)
            phpHealthTimeout="${1#*=}"
            shift
            ;;
        --skip-service-stop)
            stopService=0
            shift
            ;;
        --apply)
            apply=1
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
[[ -n "$nginxConfigPath" ]] || die "--nginx-config is required"
[[ "$phpHealthTimeout" =~ ^[1-9][0-9]*$ ]] || die "--php-health-timeout must be a positive integer"
[[ -d "$base" ]] || die "release base not found: $base"
[[ -L "$base/current" ]] || die "current release symlink not found: $base/current"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"
[[ -f "$nginxConfigPath" ]] || die "Nginx config file not found: $nginxConfigPath"
if [[ -z "$nginxBackupPath" ]]; then
    nginxBackupPath="$nginxConfigPath.php-backup"
fi
[[ -f "$nginxBackupPath" ]] || die "PHP Nginx backup config not found: $nginxBackupPath"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"

base="$(canonicalPath "$base")"
releasesPath="$(canonicalPath "$base/releases")"
currentPath="$(canonicalPath "$base/current")"
sharedStoragePath="$(readlink -f "$base/shared/storage" 2>/dev/null || true)"
[[ -n "$sharedStoragePath" && -d "$sharedStoragePath" ]] || die "shared storage directory not found: $base/shared/storage"

if [[ "$release" = /* ]]; then
    targetPath="$release"
else
    targetPath="$releasesPath/$release"
fi
[[ -d "$targetPath" ]] || die "target PHP release not found: $targetPath"
targetPath="$(canonicalPath "$targetPath")"
assertDirectReleaseChild "$targetPath" "$releasesPath"
assertPhpRelease "$targetPath"
assertReleaseStorageLinks "$targetPath"

if [[ -n "$nginxSwitchScriptOverride" ]]; then
    nginxSwitchScript="$nginxSwitchScriptOverride"
else
    nginxSwitchScript="$currentPath/deploy/scripts/switch-nginx-backend.sh"
    if [[ ! -x "$nginxSwitchScript" ]]; then
        nginxSwitchScript="$targetPath/deploy/scripts/switch-nginx-backend.sh"
    fi
fi
[[ -x "$nginxSwitchScript" ]] || die "Nginx switch script is not executable: $nginxSwitchScript"

if [[ "$apply" -ne 1 ]]; then
    printf 'ROLLBACK_TO_PHP_DRY_RUN current=%s target=%s nginx_config=%s backup=%s service=%s\n' \
        "$currentPath" "$targetPath" "$nginxConfigPath" "$nginxBackupPath" "$serviceName"
    "$nginxSwitchScript" --mode php --config "$nginxConfigPath" --backup "$nginxBackupPath"
    printf 'ROLLBACK_TO_PHP_DRY_RUN_OK target=%s\n' "$targetPath"
    exit 0
fi

tempCurrentLink="$base/.current-rollback.$$"
printCommand rm -f "$tempCurrentLink"
printCommand ln -s "$targetPath" "$tempCurrentLink"
printCommand mv -Tf "$tempCurrentLink" "$base/current"
switchCurrent "$targetPath"
printCommand "$nginxSwitchScript" --mode php --config "$nginxConfigPath" --backup "$nginxBackupPath" --apply
"$nginxSwitchScript" --mode php --config "$nginxConfigPath" --backup "$nginxBackupPath" --apply
if [[ "$stopService" -eq 1 ]]; then
    printCommand systemctl stop "$serviceName"
    systemctl stop "$serviceName"
fi
currentPathAfter="$(canonicalPath "$base/current")"
[[ "$currentPathAfter" == "$targetPath" ]] || die "current did not point to PHP target after rollback"
checkPhpHealth
printf 'ROLLBACK_TO_PHP_OK current=%s service=%s\n' "$currentPathAfter" "$serviceName"
