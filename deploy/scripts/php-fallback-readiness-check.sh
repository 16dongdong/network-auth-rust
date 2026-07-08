#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
nginxConfigPath=""
nginxBackupPath=""
rollbackScriptPath=""
nginxSwitchScriptPath=""
runRollbackDryRun=0
storageDirs=(cache logs runtime-cache build cloud-storage)

usage() {
    cat <<'USAGE'
Usage: php-fallback-readiness-check.sh [options]

Options:
  --base <path>                 Release base path. Default: /var/www/ace-network-auth
  --nginx-config <path>         Nginx site config used when running rollback dry-run.
  --nginx-backup <path>         PHP Nginx backup used when running rollback dry-run.
  --rollback-script <path>      Explicit rollback-to-php-release.sh path.
  --nginx-switch-script <path>  Explicit Nginx switch script passed to rollback dry-run.
  --rollback-dry-run            Also run rollback-to-php-release.sh without --apply.
  -h, --help                    Show this help.

This script is read-only. It finds the newest PHP release under <base>/releases,
validates that it can act as a rollback fallback, and optionally executes the
rollback script in dry-run mode.
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

canonicalPath() {
    readlink -f "$1"
}

assertDirectReleaseChild() {
    local path="$1"
    local releasesPath="$2"
    [[ "$(dirname "$path")" == "$releasesPath" ]] || die "PHP fallback is outside releases directory: $path"
}

isPhpRelease() {
    local releasePath="$1"
    [[ -f "$releasePath/index.php" ]] &&
        [[ -d "$releasePath/public" ]] &&
        [[ -d "$releasePath/config" ]] &&
        [[ ! -x "$releasePath/network-auth-rust" ]]
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

findNewestPhpRelease() {
    local releasesPath="$1"
    local newestPath=""
    local newestName=""
    local releasePath
    local releaseName

    while IFS= read -r -d '' releasePath; do
        isPhpRelease "$releasePath" || continue
        releaseName="$(basename "$releasePath")"
        if [[ -z "$newestName" || "$releaseName" > "$newestName" ]]; then
            newestName="$releaseName"
            newestPath="$releasePath"
        fi
    done < <(find "$releasesPath" -mindepth 1 -maxdepth 1 -type d -print0)

    [[ -n "$newestPath" ]] || return 1
    printf '%s' "$newestPath"
}

assertPhpFallback() {
    local releasePath="$1"
    [[ -f "$releasePath/index.php" ]] || die "PHP fallback entry file not found: $releasePath/index.php"
    [[ -d "$releasePath/public" ]] || die "PHP fallback public directory not found: $releasePath/public"
    [[ -d "$releasePath/config" ]] || die "PHP fallback config directory not found: $releasePath/config"
    [[ ! -x "$releasePath/network-auth-rust" ]] || die "PHP fallback looks like a Rust release: $releasePath"
}

assertStorageLinks() {
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
        [[ -n "$releaseStorageTarget" ]] || die "PHP fallback storage link not found: $releaseStoragePath"
        [[ "$releaseStorageTarget" == "$sharedStorageChildPath" ]] || die "PHP fallback storage must point to shared storage: $releaseStoragePath -> $releaseStorageTarget"
    done
}

resolveRollbackScript() {
    if [[ -n "$rollbackScriptPath" ]]; then
        [[ -x "$rollbackScriptPath" ]] || die "rollback script is not executable: $rollbackScriptPath"
        printf '%s' "$rollbackScriptPath"
        return
    fi
    for candidate in \
        "$currentPath/deploy/scripts/rollback-to-php-release.sh" \
        "$phpFallbackPath/deploy/scripts/rollback-to-php-release.sh"; do
        if [[ -x "$candidate" ]]; then
            printf '%s' "$candidate"
            return
        fi
    done
    die "rollback script not found; pass --rollback-script"
}

runRollbackCheck() {
    [[ "$runRollbackDryRun" -eq 1 ]] || {
        printf 'PHP_FALLBACK_ROLLBACK_DRY_RUN_SKIPPED\n'
        return
    }
    [[ -n "$nginxConfigPath" ]] || die "--nginx-config is required with --rollback-dry-run"
    [[ -f "$nginxConfigPath" ]] || die "Nginx config file not found: $nginxConfigPath"
    local rollbackScript
    local rollbackArgs
    rollbackScript="$(resolveRollbackScript)"
    rollbackArgs=(
        "$rollbackScript"
        --base "$base"
        --release "$phpFallbackPath"
        --nginx-config "$nginxConfigPath"
    )
    if [[ -n "$nginxBackupPath" ]]; then
        rollbackArgs+=(--nginx-backup "$nginxBackupPath")
    fi
    if [[ -n "$nginxSwitchScriptPath" ]]; then
        rollbackArgs+=(--nginx-switch-script "$nginxSwitchScriptPath")
    fi
    bash "${rollbackArgs[@]}" >/dev/null
    printf 'PHP_FALLBACK_ROLLBACK_DRY_RUN_OK script=%s\n' "$rollbackScript"
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
        --rollback-dry-run)
            runRollbackDryRun=1
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

[[ -d "$base" ]] || die "release base not found: $base"
[[ -L "$base/current" ]] || die "current release symlink not found: $base/current"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"

base="$(canonicalPath "$base")"
releasesPath="$(canonicalPath "$base/releases")"
currentPath="$(canonicalPath "$base/current")"
sharedStoragePath="$(readlink -f "$base/shared/storage" 2>/dev/null || true)"
[[ -d "$currentPath" ]] || die "current release target is invalid: $base/current"
[[ -n "$sharedStoragePath" && -d "$sharedStoragePath" ]] || die "shared storage directory not found: $base/shared/storage"
assertDirectReleaseChild "$currentPath" "$releasesPath"

phpFallbackPath="$(findNewestPhpRelease "$releasesPath" || true)"
[[ -n "$phpFallbackPath" ]] || die "no PHP fallback release found under $releasesPath"
phpFallbackPath="$(canonicalPath "$phpFallbackPath")"
assertDirectReleaseChild "$phpFallbackPath" "$releasesPath"
assertPhpFallback "$phpFallbackPath"
assertStorageLinks "$phpFallbackPath"
currentRuntime="$(detectCurrentRuntime "$currentPath")"

runRollbackCheck
printf 'PHP_FALLBACK_READINESS_OK base=%s current=%s current_runtime=%s php_fallback=%s\n' \
    "$base" "$currentPath" "$currentRuntime" "$phpFallbackPath"
