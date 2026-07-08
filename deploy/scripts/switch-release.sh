#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
release=""
owner="nginx:nginx"
keep="3"
service_name="network-auth-rust"
health_url="http://127.0.0.1:18080/health"
public_health_url=""
remote_cloud_summary_url="http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary"
admin_login_url="http://127.0.0.1:18080/admin/login/"
admin_console_url="http://127.0.0.1:18080/admin/console/"
admin_session_url="http://127.0.0.1:18080/sub_admin/admin_session.php"
php_bin="php"
php_tools_root=""
apply=0
restart_service=1
run_health=1
run_remote_api=1
run_web_entries=1
rollback_on_failure=1
require_config_symlink=0
startup_timeout_seconds=10
storage_dirs=(cache logs runtime-cache build cloud-storage)
static_asset_urls=()

usage() {
    cat <<'USAGE'
Usage: switch-release.sh --release <name-or-path> [options]

Options:
  --release <name-or-path>  Target release name under <base>/releases, or an absolute release path.
  --base <path>             Release base path. Default: /var/www/ace-network-auth
  --owner <user[:group]>    Runtime owner used by prepare-release-storage. Default: nginx:nginx
  --keep <count>            Release count kept by prune-releases. Default: 3
  --service <name>          systemd service restarted after switching. Default: network-auth-rust
  --health-url <url>        Local Rust health URL. Default: http://127.0.0.1:18080/health
  --public-health-url <url> Optional public health URL checked through Nginx.
  --remote-cloud-summary-url <url>
                             Remote API cloud-storage summary URL checked without HMAC.
  --admin-login-url <url>   Admin login page URL. Default: http://127.0.0.1:18080/admin/login/
  --admin-console-url <url> Admin console URL. Default: http://127.0.0.1:18080/admin/console/
  --admin-session-url <url> Legacy admin session bridge URL.
  --static-asset-url <url>  Add a static asset URL passed to release smoke. Can be repeated.
  --php-bin <path>          PHP binary for optional PHP release-tool parity. Default: php
  --php-tools-root <path>   Optional PHP project root containing tools/scripts/*.php.
  --skip-service-restart    Do not restart systemd service after switching.
  --require-config-symlink  Require target config and smoke config path to be valid symlinks.
  --skip-health             Do not run health URL checks.
  --skip-remote-api         Do not run unsigned remote API route check.
  --skip-web-entry          Do not run admin login and console entry checks.
  --no-rollback             Do not restore previous current if post-switch checks fail.
  --startup-timeout <sec>   Seconds to wait for local health after service restart. Default: 10
  --apply                   Actually update current, restart service, run smoke, and prune old releases.
  -h, --help                Show this help.

The default mode is dry-run. It validates the target release and runs target preflight, but it does not
change current, restart services, or delete releases.
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

need_value() {
    local name="$1"
    local value="${2:-}"
    [[ -n "$value" ]] || die "$name requires a value"
    printf '%s' "$value"
}

print_command() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
}

run_command() {
    print_command "$@"
    "$@"
}

canonical_path() {
    local path="$1"
    readlink -f "$path"
}

assert_direct_release_child() {
    local path="$1"
    local releases_path="$2"
    local parent
    parent="$(dirname "$path")"
    [[ "$parent" == "$releases_path" ]] || die "release path is outside releases directory: $path"
}

assert_release_storage_links() {
    local release_path="$1"
    local label="$2"
    local directory_name
    local release_storage_path
    local release_storage_target
    local shared_storage_child_path

    for directory_name in "${storage_dirs[@]}"; do
        release_storage_path="$release_path/storage/$directory_name"
        shared_storage_child_path="$(readlink -f "$shared_storage_path/$directory_name" 2>/dev/null || true)"
        release_storage_target="$(readlink -f "$release_storage_path" 2>/dev/null || true)"
        [[ -n "$shared_storage_child_path" && -d "$shared_storage_child_path" ]] || die "$label shared storage child not found: $base/shared/storage/$directory_name"
        [[ -n "$release_storage_target" ]] || die "$label storage link not found: $release_storage_path"
        [[ "$release_storage_target" == "$shared_storage_child_path" ]] || die "$label storage must point to shared storage: $release_storage_path -> $release_storage_target"
    done
}

validate_keep_count() {
    [[ "$keep" =~ ^[0-9]+$ ]] || die "release keep count must be a positive integer"
    (( 10#$keep >= 1 && 10#$keep <= 50 )) || die "release keep count must be between 1 and 50"
}

validate_startup_timeout() {
    [[ "$startup_timeout_seconds" =~ ^[0-9]+$ ]] || die "startup timeout must be a positive integer"
    (( 10#$startup_timeout_seconds >= 1 && 10#$startup_timeout_seconds <= 120 )) || die "startup timeout must be between 1 and 120"
}

assertRustHealthResponse() {
    local response_body="$1"
    local label="$2"

    if ! printf '%s' "$response_body" | grep -Eq '^[[:space:]]*\{'; then
        printf 'ERROR: %s did not return a JSON object\n' "$label" >&2
        return 1
    fi
    if ! printf '%s' "$response_body" | grep -Eq '"runtime"[[:space:]]*:[[:space:]]*"rust"'; then
        printf 'ERROR: %s did not report Rust runtime\n' "$label" >&2
        return 1
    fi
}

assert_json_content_type() {
    local header_file="$1"
    local label="$2"

    if ! grep -Eiq '^content-type:[[:space:]]*application/json([;[:space:]]|$)' "$header_file"; then
        printf 'ERROR: %s did not return JSON content type\n' "$label" >&2
        return 1
    fi
}

switch_current() {
    local target="$1"
    local temp_link="$base/.current-next.$$"
    rm -f "$temp_link"
    ln -s "$target" "$temp_link"
    mv -Tf "$temp_link" "$base/current"
}

target_preflight() {
    run_command "$target_binary" preflight \
        --strict \
        --config "$target_config" \
        --database \
        --public-root "$target_path/public" \
        --schema "$target_path/resources/install/schema.sql" \
        --storage-root "$target_path/storage"
}

check_health() {
    [[ "$run_health" -eq 1 ]] || return 0
    local health_response
    local health_headers
    local deadline
    local ready
    if ! command -v curl >/dev/null 2>&1; then
        printf 'ERROR: curl is required for health checks\n' >&2
        return 1
    fi
    health_headers="$(mktemp)" || return 1
    print_command curl -fsS "$health_url"
    deadline=$((SECONDS + startup_timeout_seconds))
    ready=0
    while (( SECONDS <= deadline )); do
        if health_response="$(curl -fsS -D "$health_headers" "$health_url" 2>/dev/null)" &&
            assert_json_content_type "$health_headers" "local health URL" &&
            assertRustHealthResponse "$health_response" "local health URL"; then
            ready=1
            break
        fi
        : >"$health_headers"
        sleep 1
    done
    rm -f "$health_headers"
    if [[ "$ready" -ne 1 ]]; then
        printf 'ERROR: local health URL check failed\n' >&2
        return 1
    fi
    if [[ -n "$public_health_url" ]]; then
        health_headers="$(mktemp)" || return 1
        print_command curl -fsS "$public_health_url"
        if ! health_response="$(curl -fsS -D "$health_headers" "$public_health_url")"; then
            rm -f "$health_headers"
            printf 'ERROR: public health URL check failed\n' >&2
            return 1
        fi
        assert_json_content_type "$health_headers" "public health URL" || { rm -f "$health_headers"; return 1; }
        rm -f "$health_headers"
        assertRustHealthResponse "$health_response" "public health URL" || return
    fi
}

restart_runtime_service() {
    [[ "$restart_service" -eq 1 ]] || return 0
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required for service restart"
    run_command systemctl restart "$service_name"
}

stop_runtime_service() {
    [[ "$restart_service" -eq 1 ]] || return 0
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required for service stop"
    run_command systemctl stop "$service_name"
}

release_runtime_kind() {
    local release_path="$1"
    local binary_path="$release_path/network-auth-rust"
    local config_path="$release_path/config/local.php"
    local smoke_path="$release_path/deploy/scripts/release-smoke.sh"

    if [[ -e "$binary_path" || -e "$smoke_path" ]]; then
        [[ -x "$binary_path" ]] || die "rollback Rust binary is not executable: $binary_path"
        [[ -f "$config_path" ]] || die "rollback Rust config file not found: $config_path"
        [[ -f "$smoke_path" ]] || die "rollback Rust smoke script not found: $smoke_path"
        [[ -x "$smoke_path" ]] || die "rollback Rust smoke script is not executable: $smoke_path"
        printf 'rust'
        return
    fi

    [[ -f "$release_path/index.php" ]] || die "rollback PHP entry file not found: $release_path/index.php"
    [[ -d "$release_path/public" ]] || die "rollback PHP public directory not found: $release_path/public"
    [[ -d "$release_path/config" ]] || die "rollback PHP config directory not found: $release_path/config"
    printf 'php'
}

verify_php_rollback_release() {
    local previous_current="$1"
    assert_release_storage_links "$previous_current" "rollback PHP release"
    printf 'ROLLBACK_PHP_RELEASE_OK current=%s\n' "$previous_current" >&2
}

run_release_smoke_for() {
    local smoke_script="$1"
    local smoke_binary="$2"
    local smoke_config="$3"
    local smoke_args=(
        "$smoke_script"
        --base "$base"
        --binary "$smoke_binary"
        --config "$smoke_config"
        --owner "$owner"
        --keep "$keep"
        --health-url "$health_url"
        --remote-cloud-summary-url "$remote_cloud_summary_url"
        --admin-login-url "$admin_login_url"
        --admin-console-url "$admin_console_url"
        --admin-session-url "$admin_session_url"
    )
    if [[ -n "$public_health_url" ]]; then
        smoke_args+=(--public-health-url "$public_health_url")
    fi
    for static_asset_url in "${static_asset_urls[@]}"; do
        smoke_args+=(--static-asset-url "$static_asset_url")
    done
    if [[ -n "$php_tools_root" ]]; then
        smoke_args+=(--php-bin "$php_bin" --php-tools-root "$php_tools_root")
    fi
    if [[ "$restart_service" -eq 1 ]]; then
        smoke_args+=(--service "$service_name")
    fi
    if [[ "$run_health" -eq 0 ]]; then
        smoke_args+=(--skip-health)
    fi
    if [[ "$run_remote_api" -eq 0 ]]; then
        smoke_args+=(--skip-remote-api)
    fi
    if [[ "$run_web_entries" -eq 0 ]]; then
        smoke_args+=(--skip-web-entry)
    fi
    if [[ "$require_config_symlink" -eq 1 ]]; then
        smoke_args+=(--require-config-symlink)
    fi
    run_command bash "${smoke_args[@]}"
}

run_release_smoke() {
    run_release_smoke_for "$target_smoke" "$target_binary" "$target_config"
}

target_package_check() {
    local package_check_script="$target_path/deploy/scripts/release-package-check.sh"
    [[ -f "$package_check_script" ]] || die "release package check script not found: $package_check_script"
    [[ -x "$package_check_script" ]] || die "release package check script is not executable: $package_check_script"
    local package_check_args=("$package_check_script" --release "$target_path")
    if [[ "$require_config_symlink" -eq 1 ]]; then
        package_check_args+=(--require-config-symlink)
    fi
    run_command bash "${package_check_args[@]}"
}

post_switch_checks() {
    run_command "$target_binary" prepare-release-storage --base "$base" --owner "$owner" || return
    target_preflight || return
    restart_runtime_service || return
    check_health || return
    run_release_smoke || return
}

rollback_current() {
    local previous_current="$1"
    local previous_runtime
    local previous_binary="$previous_current/network-auth-rust"
    local previous_config="$previous_current/config/local.php"
    local previous_smoke="$previous_current/deploy/scripts/release-smoke.sh"
    [[ "$rollback_on_failure" -eq 1 ]] || return 1
    printf 'ROLLBACK_START previous=%s\n' "$previous_current" >&2
    switch_current "$previous_current"
    previous_runtime="$(release_runtime_kind "$previous_current")"
    if [[ "$previous_runtime" == "rust" ]]; then
        restart_runtime_service || return
        check_health || return
        run_release_smoke_for "$previous_smoke" "$previous_binary" "$previous_config" || return
        printf 'ROLLBACK_SMOKE_OK current=%s\n' "$previous_current" >&2
    else
        stop_runtime_service || return
        verify_php_rollback_release "$previous_current" || return
    fi
    printf 'ROLLBACK_OK current=%s\n' "$previous_current" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            release="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --release=*)
            release="${1#*=}"
            shift
            ;;
        --base)
            base="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --base=*)
            base="${1#*=}"
            shift
            ;;
        --owner)
            owner="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --owner=*)
            owner="${1#*=}"
            shift
            ;;
        --keep)
            keep="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --keep=*)
            keep="${1#*=}"
            shift
            ;;
        --service)
            service_name="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --service=*)
            service_name="${1#*=}"
            shift
            ;;
        --health-url)
            health_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --health-url=*)
            health_url="${1#*=}"
            shift
            ;;
        --public-health-url)
            public_health_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --public-health-url=*)
            public_health_url="${1#*=}"
            shift
            ;;
        --remote-cloud-summary-url)
            remote_cloud_summary_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --remote-cloud-summary-url=*)
            remote_cloud_summary_url="${1#*=}"
            shift
            ;;
        --admin-login-url)
            admin_login_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --admin-login-url=*)
            admin_login_url="${1#*=}"
            shift
            ;;
        --admin-console-url)
            admin_console_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --admin-console-url=*)
            admin_console_url="${1#*=}"
            shift
            ;;
        --admin-session-url)
            admin_session_url="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --admin-session-url=*)
            admin_session_url="${1#*=}"
            shift
            ;;
        --static-asset-url)
            static_asset_urls+=("$(need_value "$1" "${2:-}")")
            shift 2
            ;;
        --static-asset-url=*)
            static_asset_urls+=("${1#*=}")
            shift
            ;;
        --php-bin)
            php_bin="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --php-bin=*)
            php_bin="${1#*=}"
            shift
            ;;
        --php-tools-root)
            php_tools_root="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --php-tools-root=*)
            php_tools_root="${1#*=}"
            shift
            ;;
        --skip-service-restart)
            restart_service=0
            shift
            ;;
        --require-config-symlink)
            require_config_symlink=1
            shift
            ;;
        --skip-health)
            run_health=0
            shift
            ;;
        --skip-remote-api)
            run_remote_api=0
            shift
            ;;
        --skip-web-entry)
            run_web_entries=0
            shift
            ;;
        --no-rollback)
            rollback_on_failure=0
            shift
            ;;
        --startup-timeout)
            startup_timeout_seconds="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --startup-timeout=*)
            startup_timeout_seconds="${1#*=}"
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
validate_keep_count
validate_startup_timeout
[[ -d "$base" ]] || die "release base not found: $base"
[[ -L "$base/current" ]] || die "current release symlink not found: $base/current"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"

base_path="$(canonical_path "$base")"
releases_path="$(canonical_path "$base/releases")"
current_path="$(canonical_path "$base/current")"
shared_storage_path="$(readlink -f "$base/shared/storage" 2>/dev/null || true)"
[[ -d "$current_path" ]] || die "current release target is invalid: $base/current"
[[ -n "$shared_storage_path" && -d "$shared_storage_path" ]] || die "shared storage directory not found: $base/shared/storage"
assert_direct_release_child "$current_path" "$releases_path"

if [[ "$release" = /* ]]; then
    release_candidate="$release"
else
    release_candidate="$releases_path/$release"
fi
[[ -d "$release_candidate" ]] || die "target release not found: $release_candidate"
target_path="$(canonical_path "$release_candidate")"
assert_direct_release_child "$target_path" "$releases_path"

target_binary="$target_path/network-auth-rust"
target_config="$target_path/config/local.php"
target_smoke="$target_path/deploy/scripts/release-smoke.sh"
[[ -x "$target_binary" ]] || die "network-auth-rust binary is not executable: $target_binary"
[[ -f "$target_config" ]] || die "config file not found: $target_config"
if [[ "$require_config_symlink" -eq 1 ]]; then
    [[ -L "$target_config" ]] || die "config file is not a symlink: $target_config"
    target_config_path="$(readlink -f "$target_config" 2>/dev/null || true)"
    [[ -n "$target_config_path" && -f "$target_config_path" ]] || die "config symlink target is invalid: $target_config"
fi
[[ -f "$target_smoke" ]] || die "release smoke script not found: $target_smoke"
[[ -x "$target_smoke" ]] || die "release smoke script is not executable: $target_smoke"
assert_release_storage_links "$target_path" "target release"
target_package_check

if [[ "$target_path" == "$current_path" ]]; then
    printf 'TARGET_ALREADY_CURRENT current=%s\n' "$current_path"
else
    printf 'TARGET_READY current=%s target=%s\n' "$current_path" "$target_path"
fi

target_preflight

if [[ "$apply" -ne 1 ]]; then
    printf 'DRY_RUN_OK base=%s current=%s target=%s\n' "$base_path" "$current_path" "$target_path"
    printf 'DRY_RUN_PLAN switch current to target, run prepare-release-storage, restart service, run release-smoke, prune old releases.\n'
    exit 0
fi

if [[ "$target_path" != "$current_path" ]]; then
    print_command ln -s "$target_path" "$base/.current-next.$$"
    print_command mv -Tf "$base/.current-next.$$" "$base/current"
    switch_current "$target_path"
fi

if post_switch_checks; then
    printf 'SWITCH_RELEASE_OK base=%s current=%s\n' "$base_path" "$target_path"
    if ! run_command "$target_binary" prune-releases --base "$base" --keep "$keep"; then
        printf 'PRUNE_RELEASES_FAILED current=%s\n' "$target_path" >&2
        exit 1
    fi
    exit 0
fi

printf 'SWITCH_RELEASE_FAILED target=%s\n' "$target_path" >&2
rollback_current "$current_path"
exit 1
