#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
release=""
listen="127.0.0.1:18081"
require_config_symlink=0
run_package_check=1
run_preflight=1
run_remote_api=1
run_web_entries=1
startup_timeout_seconds=10
storage_dirs=(cache logs runtime-cache build cloud-storage)
static_asset_urls=()

usage() {
    cat <<'USAGE'
Usage: pre-switch-release-smoke.sh --release <name-or-path> [options]

Options:
  --release <name-or-path>  Target release name under <base>/releases, or an absolute release path.
  --base <path>             Release base path. Default: /var/www/ace-network-auth
  --listen <addr:port>      Temporary Rust listen address. Default: 127.0.0.1:18081
  --require-config-symlink  Require target config/local.php to be a valid symlink.
  --skip-package-check      Skip offline release-package-check.sh.
  --skip-preflight          Skip Rust preflight.
  --skip-remote-api         Skip unsigned remote API route check.
  --skip-web-entry          Skip admin login, console, legacy session, and static asset checks.
  --static-asset-url <url>  Add a static asset URL. Can be repeated.
  --startup-timeout <sec>   Seconds to wait for health before failing. Default: 10
  -h, --help                Show this help.

This script does not modify current, systemd, Nginx, or release files. It starts
the target release binary on a temporary local port, runs HTTP probes, then stops it.
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

assert_direct_release_child() {
    local path="$1"
    local releases_path="$2"
    local parent
    parent="$(dirname "$path")"
    [[ "$parent" == "$releases_path" ]] || die "release path is outside releases directory: $path"
}

assert_json_content_type() {
    local header_file="$1"
    local label="$2"
    grep -Eiq '^content-type:[[:space:]]*application/json([;[:space:]]|$)' "$header_file" ||
        die "$label did not return JSON content type"
}

assert_html_content_type() {
    local header_file="$1"
    local label="$2"
    grep -Eiq '^content-type:[[:space:]]*text/html([;[:space:]]|$)' "$header_file" ||
        die "$label did not return HTML content type"
}

assert_http_status() {
    local header_file="$1"
    local expected_status="$2"
    local label="$3"
    grep -Eq "^HTTP/[0-9.]+ $expected_status([[:space:]]|$)" "$header_file" ||
        die "$label did not return HTTP $expected_status"
}

assert_rust_health_response() {
    local response_body="$1"
    local label="$2"
    printf '%s' "$response_body" | grep -Eq '^[[:space:]]*\{' ||
        die "$label did not return a JSON object"
    printf '%s' "$response_body" | grep -Eq '"runtime"[[:space:]]*:[[:space:]]*"rust"' ||
        die "$label did not report Rust runtime"
}

assert_json_error_response() {
    local response_body="$1"
    local expected_error="$2"
    local label="$3"
    printf '%s' "$response_body" | grep -Eq '^[[:space:]]*\{' ||
        die "$label did not return a JSON object"
    printf '%s' "$response_body" | grep -Eq "\"error\"[[:space:]]*:[[:space:]]*\"$expected_error\"" ||
        die "$label did not return error $expected_error"
}

assert_static_asset_content() {
    local static_asset_url="$1"
    local static_asset_file="$2"
    local webp_prefix
    local webp_signature

    case "$static_asset_url" in
        */assets/layui/layui.js)
            grep -Fq 'layui.define' "$static_asset_file" ||
                die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/js/app.js)
            grep -Fq '(function (app)' "$static_asset_file" ||
                die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/css/app.css)
            grep -Fq '.auth-admin' "$static_asset_file" ||
                die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/js/img/brand-avatar.webp)
            webp_prefix="$(dd if="$static_asset_file" bs=1 count=4 2>/dev/null)"
            webp_signature="$(dd if="$static_asset_file" bs=1 skip=8 count=4 2>/dev/null)"
            [[ "$webp_prefix" == "RIFF" && "$webp_signature" == "WEBP" ]] ||
                die "static asset is not a WebP file: $static_asset_url"
            ;;
    esac
}

assert_release_storage_links() {
    local release_path="$1"
    local shared_storage_path="$2"
    local directory_name
    local release_storage_path
    local release_storage_target
    local shared_storage_child_path

    for directory_name in "${storage_dirs[@]}"; do
        release_storage_path="$release_path/storage/$directory_name"
        shared_storage_child_path="$(readlink -f "$shared_storage_path/$directory_name" 2>/dev/null || true)"
        release_storage_target="$(readlink -f "$release_storage_path" 2>/dev/null || true)"
        [[ -n "$shared_storage_child_path" && -d "$shared_storage_child_path" ]] ||
            die "shared storage child not found: $shared_storage_path/$directory_name"
        [[ -n "$release_storage_target" ]] ||
            die "release storage link not found: $release_storage_path"
        [[ "$release_storage_target" == "$shared_storage_child_path" ]] ||
            die "release storage must point to shared storage: $release_storage_path -> $release_storage_target"
    done
}

validate_positive_integer() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 ]] ||
        die "$label must be a positive integer"
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
        --listen)
            listen="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --listen=*)
            listen="${1#*=}"
            shift
            ;;
        --require-config-symlink)
            require_config_symlink=1
            shift
            ;;
        --skip-package-check)
            run_package_check=0
            shift
            ;;
        --skip-preflight)
            run_preflight=0
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
        --static-asset-url)
            static_asset_urls+=("$(need_value "$1" "${2:-}")")
            shift 2
            ;;
        --static-asset-url=*)
            static_asset_urls+=("${1#*=}")
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
validate_positive_integer "startup timeout" "$startup_timeout_seconds"
[[ -d "$base" ]] || die "release base not found: $base"
[[ -d "$base/releases" ]] || die "releases directory not found: $base/releases"

base_path="$(readlink -f "$base")"
releases_path="$(readlink -f "$base/releases")"
shared_storage_path="$(readlink -f "$base/shared/storage" 2>/dev/null || true)"
[[ -n "$shared_storage_path" && -d "$shared_storage_path" ]] ||
    die "shared storage directory not found: $base/shared/storage"

if [[ "$release" = /* ]]; then
    release_candidate="$release"
else
    release_candidate="$releases_path/$release"
fi
[[ -d "$release_candidate" ]] || die "target release not found: $release_candidate"
release_path="$(readlink -f "$release_candidate")"
assert_direct_release_child "$release_path" "$releases_path"

binary="$release_path/network-auth-rust"
config="$release_path/config/local.php"
schema="$release_path/resources/install/schema.sql"
public_root="$release_path/public"
storage_root="$release_path/storage"
install_lock="$base_path/shared/storage/cache/install.lock"
package_check_script="$release_path/deploy/scripts/release-package-check.sh"

[[ -x "$binary" ]] || die "network-auth-rust binary is not executable: $binary"
[[ -f "$config" ]] || die "config file not found: $config"
[[ -f "$schema" ]] || die "schema file not found: $schema"
[[ -d "$public_root" ]] || die "public root not found: $public_root"
[[ -d "$storage_root" ]] || die "storage root not found: $storage_root"
if [[ "$require_config_symlink" -eq 1 ]]; then
    [[ -L "$config" ]] || die "config file is not a symlink: $config"
    config_target="$(readlink -f "$config" 2>/dev/null || true)"
    [[ -n "$config_target" && -f "$config_target" ]] || die "config symlink target is invalid: $config"
fi

assert_release_storage_links "$release_path" "$shared_storage_path"
if [[ "$run_package_check" -eq 1 ]]; then
    [[ -x "$package_check_script" ]] || die "release package check script is not executable: $package_check_script"
    package_check_args=("$package_check_script" --release "$release_path")
    if [[ "$require_config_symlink" -eq 1 ]]; then
        package_check_args+=(--require-config-symlink)
    fi
    bash "${package_check_args[@]}"
fi

if [[ "$run_preflight" -eq 1 ]]; then
    "$binary" preflight \
        --strict \
        --config "$config" \
        --database \
        --public-root "$public_root" \
        --schema "$schema" \
        --storage-root "$storage_root"
fi

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

"$binary" serve \
    --listen "$listen" \
    --config "$config" \
    --public-root "$public_root" \
    --schema "$schema" \
    --install-lock "$install_lock" >"$scratch/server.log" 2>&1 &
server_pid="$!"

base_url="http://$listen"
health_url="$base_url/health"
health_headers="$scratch/health.headers"
health_body="$scratch/health.body"
deadline=$((SECONDS + startup_timeout_seconds))
health_ready=0
while (( SECONDS <= deadline )); do
    if curl -fsS -D "$health_headers" "$health_url" >"$health_body" 2>/dev/null; then
        health_ready=1
        break
    fi
    sleep 1
done
if [[ "$health_ready" -ne 1 ]]; then
    tail -80 "$scratch/server.log" >&2 || true
    die "Rust release did not become healthy on $listen"
fi
assert_json_content_type "$health_headers" "temporary health URL"
assert_rust_health_response "$(cat "$health_body")" "temporary health URL"

if [[ "$run_remote_api" -eq 1 ]]; then
    remote_api_headers="$scratch/remote-api.headers"
    remote_api_body="$scratch/remote-api.body"
    curl -sS -D "$remote_api_headers" -o "$remote_api_body" \
        -X POST -H 'Content-Type: application/json' --data '{}' \
        "$base_url/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary"
    assert_http_status "$remote_api_headers" "401" "remote cloud-storage summary route"
    assert_json_content_type "$remote_api_headers" "remote cloud-storage summary route"
    assert_json_error_response "$(cat "$remote_api_body")" "REMOTE_API_HEADER_MISSING" "remote cloud-storage summary route"
fi

if [[ "$run_web_entries" -eq 1 ]]; then
    admin_login_headers="$scratch/admin-login.headers"
    admin_login_body="$scratch/admin-login.body"
    curl -fsS -D "$admin_login_headers" "$base_url/admin/login/" >"$admin_login_body"
    assert_http_status "$admin_login_headers" "200" "admin login page"
    assert_html_content_type "$admin_login_headers" "admin login page"
    admin_login_response="$(cat "$admin_login_body")"
    case "$admin_login_response" in
        *"后台登录"*name=\"username\"*) ;;
        *) die "admin login page did not contain expected form markers" ;;
    esac

    admin_console_headers="$scratch/admin-console.headers"
    curl -sS -D "$admin_console_headers" -o /dev/null "$base_url/admin/console/"
    grep -Eq '^HTTP/[0-9.]+ 302 ' "$admin_console_headers" ||
        die "admin console without session did not redirect"
    grep -Eiq '^location: /admin/login/?[[:space:]]*$' "$admin_console_headers" ||
        die "admin console redirect target is not /admin/login/"

    admin_session_headers="$scratch/admin-session.headers"
    admin_session_body="$scratch/admin-session.body"
    curl -sS -D "$admin_session_headers" -o "$admin_session_body" \
        -X POST -H 'Content-Type: application/json' --data '{}' \
        "$base_url/sub_admin/admin_session.php"
    assert_http_status "$admin_session_headers" "401" "legacy admin session bridge"
    assert_json_content_type "$admin_session_headers" "legacy admin session bridge"
    assert_json_error_response "$(cat "$admin_session_body")" "ADMIN_LOGIN_REQUIRED" "legacy admin session bridge"

    if [[ "${#static_asset_urls[@]}" -eq 0 ]]; then
        static_asset_urls=(
            "$base_url/assets/layui/layui.js"
            "$base_url/frontend/admin-console/js/app.js"
            "$base_url/frontend/admin-console/css/app.css"
            "$base_url/frontend/admin-console/js/img/brand-avatar.webp"
        )
    fi
    static_asset_index=0
    for static_asset_url in "${static_asset_urls[@]}"; do
        static_asset_file="$scratch/static-asset-$static_asset_index"
        curl -fsS -o "$static_asset_file" "$static_asset_url" ||
            die "static asset is not reachable: $static_asset_url"
        [[ -s "$static_asset_file" ]] || die "static asset is empty: $static_asset_url"
        assert_static_asset_content "$static_asset_url" "$static_asset_file"
        static_asset_index=$((static_asset_index + 1))
    done
fi

printf 'PRE_SWITCH_RELEASE_SMOKE_OK release=%s listen=%s\n' "$release_path" "$listen"
