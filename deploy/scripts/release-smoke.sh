#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
owner="nginx:nginx"
keep="3"
binary=""
config=""
health_url="http://127.0.0.1:18080/health"
public_health_url=""
health_timeout=10
remote_cloud_summary_url="http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary"
admin_login_url="http://127.0.0.1:18080/admin/login/"
admin_console_url="http://127.0.0.1:18080/admin/console/"
admin_session_url="http://127.0.0.1:18080/sub_admin/admin_session.php"
php_bin="php"
php_tools_root=""
service_name=""
run_preflight=1
run_health=1
run_remote_api=1
run_web_entries=1
require_config_symlink=0
storage_dirs=(cache logs runtime-cache build cloud-storage)
static_asset_urls=(
    "http://127.0.0.1:18080/assets/layui/layui.js"
    "http://127.0.0.1:18080/frontend/admin-console/js/app.js"
    "http://127.0.0.1:18080/frontend/admin-console/css/app.css"
    "http://127.0.0.1:18080/frontend/admin-console/js/img/brand-avatar.webp"
)

usage() {
    cat <<'USAGE'
Usage: release-smoke.sh [options]

Options:
  --base <path>              Release base path. Default: /var/www/ace-network-auth
  --binary <path>            network-auth-rust binary. Default: <base>/current/network-auth-rust
  --config <path>            PHP-style config path. Default: <base>/current/config/local.php
  --owner <user[:group]>     Runtime owner used by prepare-release-storage dry-run.
  --keep <count>             Release count kept by prune-releases dry-run. Default: 3
  --health-url <url>         Local Rust health URL. Default: http://127.0.0.1:18080/health
  --public-health-url <url>  Optional public health URL checked through Nginx.
  --health-timeout <s>       Seconds to wait for health readiness. Default: 10
  --remote-cloud-summary-url <url>
                              Remote API cloud-storage summary URL checked without HMAC.
  --admin-login-url <url>    Admin login page URL. Default: http://127.0.0.1:18080/admin/login/
  --admin-console-url <url>  Admin console URL. Default: http://127.0.0.1:18080/admin/console/
  --admin-session-url <url>  Legacy admin session bridge URL.
  --static-asset-url <url>   Add a static asset URL checked with GET. Can be repeated.
  --php-bin <path>           PHP binary for optional PHP release-tool parity. Default: php
  --php-tools-root <path>    Optional PHP project root containing tools/scripts/*.php.
  --service <name>           Optional systemd service name to check with systemctl is-active.
  --require-config-symlink   Require config path to be a valid symlink.
  --skip-preflight           Skip Rust preflight.
  --skip-health              Skip health URL checks.
  --skip-remote-api          Skip unsigned remote API route check.
  --skip-web-entry           Skip admin login and console entry checks.
  -h, --help                 Show this help.
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
    [[ "$parent" == "$releases_path" ]] || die "current release is outside releases directory: $path"
}

assert_file_argument_inside_current() {
    local label="$1"
    local path="$2"
    local current_path="$3"
    local parent
    parent="$(cd "$(dirname "$path")" && pwd -P)" || die "$label parent directory is invalid: $path"
    case "$parent/" in
        "$current_path"/*|"$current_path/") ;;
        *) die "$label path is outside current release: $path" ;;
    esac
}

assert_static_asset_content() {
    local static_asset_url="$1"
    local static_asset_file="$2"
    local webp_prefix
    local webp_signature

    case "$static_asset_url" in
        */assets/layui/layui.js)
            grep -Fq 'layui.define' "$static_asset_file" || die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/js/app.js)
            grep -Fq '(function (app)' "$static_asset_file" || die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/css/app.css)
            grep -Fq '.auth-admin' "$static_asset_file" || die "static asset content marker missing: $static_asset_url"
            ;;
        */frontend/admin-console/js/img/brand-avatar.webp)
            webp_prefix="$(dd if="$static_asset_file" bs=1 count=4 2>/dev/null)"
            webp_signature="$(dd if="$static_asset_file" bs=1 skip=8 count=4 2>/dev/null)"
            [[ "$webp_prefix" == "RIFF" && "$webp_signature" == "WEBP" ]] || die "static asset is not a WebP file: $static_asset_url"
            ;;
    esac
}

assert_json_error_response() {
    local response_body="$1"
    local expected_error="$2"
    local label="$3"

    printf '%s' "$response_body" | grep -Eq '^[[:space:]]*\{' || die "$label did not return a JSON object"
    printf '%s' "$response_body" | grep -Eq '"error"[[:space:]]*:[[:space:]]*"'"$expected_error"'"' || die "$label did not return $expected_error"
}

assert_json_content_type() {
    local header_file="$1"
    local label="$2"

    grep -Eiq '^content-type:[[:space:]]*application/json([;[:space:]]|$)' "$header_file" || die "$label did not return JSON content type"
}

assert_html_content_type() {
    local header_file="$1"
    local label="$2"

    grep -Eiq '^content-type:[[:space:]]*text/html([;[:space:]]|$)' "$header_file" || die "$label did not return HTML content type"
}

assert_http_status() {
    local header_file="$1"
    local expected_status="$2"
    local label="$3"

    grep -Eq '^HTTP/[0-9.]+ '"$expected_status"'([[:space:]]|$)' "$header_file" || die "$label did not return HTTP $expected_status"
}

assertRustHealthUrl() {
    local url="$1"
    local label="$2"
    local header_file="$3"
    local response_body
    local deadline
    deadline=$(( $(date +%s) + health_timeout ))

    while true; do
        response_body="$(curl -fsS -D "$header_file" "$url" 2>/dev/null || true)"
        if [[ -n "$response_body" ]]; then
            assert_json_content_type "$header_file" "$label"
            printf '%s' "$response_body" | grep -Eq '^[[:space:]]*\{' || die "$label did not return a JSON object"
            printf '%s' "$response_body" | grep -Eq '"runtime"[[:space:]]*:[[:space:]]*"rust"' || die "$label did not report Rust runtime"
            return 0
        fi

        [[ "$(date +%s)" -lt "$deadline" ]] || die "$label did not become ready"
        sleep 1
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            base="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --base=*)
            base="${1#*=}"
            shift
            ;;
        --binary)
            binary="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --binary=*)
            binary="${1#*=}"
            shift
            ;;
        --config)
            config="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --config=*)
            config="${1#*=}"
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
        --health-timeout)
            health_timeout="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --health-timeout=*)
            health_timeout="${1#*=}"
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
        --service)
            service_name="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --service=*)
            service_name="${1#*=}"
            shift
            ;;
        --require-config-symlink)
            require_config_symlink=1
            shift
            ;;
        --skip-preflight)
            run_preflight=0
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
[[ "$health_timeout" =~ ^[1-9][0-9]*$ ]] || die "--health-timeout must be a positive integer"

current_path="$(readlink -f "$base/current")"
releases_path="$(readlink -f "$base/releases")"
shared_storage_path="$(readlink -f "$base/shared/storage" 2>/dev/null || true)"

[[ -n "$current_path" && -d "$current_path" ]] || die "current release target is invalid: $base/current"
assert_direct_release_child "$current_path" "$releases_path"
[[ -n "$shared_storage_path" && -d "$shared_storage_path" ]] || die "shared storage directory not found: $base/shared/storage"

if [[ -z "$binary" ]]; then
    binary="$current_path/network-auth-rust"
fi
if [[ -z "$config" ]]; then
    config="$current_path/config/local.php"
fi

[[ -x "$binary" ]] || die "network-auth-rust binary is not executable: $binary"
[[ -f "$config" ]] || die "config file not found: $config"
assert_file_argument_inside_current "binary" "$binary" "$current_path"
assert_file_argument_inside_current "config" "$config" "$current_path"
if [[ "$require_config_symlink" -eq 1 ]]; then
    [[ -L "$config" ]] || die "config file is not a symlink: $config"
    config_target="$(readlink -f "$config" 2>/dev/null || true)"
    [[ -n "$config_target" && -f "$config_target" ]] || die "config symlink target is invalid: $config"
fi

for directory_name in "${storage_dirs[@]}"; do
    release_storage_path="$current_path/storage/$directory_name"
    shared_storage_child_path="$(readlink -f "$shared_storage_path/$directory_name" 2>/dev/null || true)"
    release_storage_target="$(readlink -f "$release_storage_path" 2>/dev/null || true)"
    [[ -n "$shared_storage_child_path" && -d "$shared_storage_child_path" ]] || die "shared storage child not found: $base/shared/storage/$directory_name"
    [[ -n "$release_storage_target" ]] || die "release storage link not found: $release_storage_path"
    [[ "$release_storage_target" == "$shared_storage_child_path" ]] || die "release storage must point to shared storage: $release_storage_path -> $release_storage_target"
done

scratch="$(mktemp -d)"
cleanup() {
    rm -rf "$scratch"
}
trap cleanup EXIT

run_capture() {
    local output_file="$1"
    shift
    printf '+ %q' "$@"
    printf '\n'
    "$@" >"$output_file"
}

rust_prepare="$scratch/rust-prepare.json"
rust_prune="$scratch/rust-prune.json"
run_capture "$rust_prepare" "$binary" prepare-release-storage --dry-run --base "$base" --owner "$owner"
run_capture "$rust_prune" "$binary" prune-releases --dry-run --base "$base" --keep "$keep"

if [[ -n "$php_tools_root" ]]; then
    php_prepare="$php_tools_root/tools/scripts/prepareReleaseStorage.php"
    php_prune="$php_tools_root/tools/scripts/pruneReleases.php"
    [[ -f "$php_prepare" ]] || die "PHP prepareReleaseStorage.php not found: $php_prepare"
    [[ -f "$php_prune" ]] || die "PHP pruneReleases.php not found: $php_prune"

    php_prepare_output="$scratch/php-prepare.json"
    php_prune_output="$scratch/php-prune.json"
    run_capture "$php_prepare_output" "$php_bin" "$php_prepare" --dry-run "--base=$base" "--owner=$owner"
    run_capture "$php_prune_output" "$php_bin" "$php_prune" --dry-run "--base=$base" "--keep=$keep"
    diff -u "$php_prepare_output" "$rust_prepare"
    diff -u "$php_prune_output" "$rust_prune"
fi

if [[ "$run_preflight" -eq 1 ]]; then
    "$binary" preflight \
        --strict \
        --config "$config" \
        --database \
        --public-root "$current_path/public" \
        --schema "$current_path/resources/install/schema.sql" \
        --storage-root "$current_path/storage"
fi

if [[ "$run_health" -eq 1 ]]; then
    command -v curl >/dev/null 2>&1 || die "curl is required for health checks"
    health_headers="$scratch/health.headers"
    assertRustHealthUrl "$health_url" "local health URL" "$health_headers"
    if [[ -n "$public_health_url" ]]; then
        public_health_headers="$scratch/public-health.headers"
        assertRustHealthUrl "$public_health_url" "public health URL" "$public_health_headers"
    fi
fi

if [[ "$run_remote_api" -eq 1 ]]; then
    command -v curl >/dev/null 2>&1 || die "curl is required for remote API checks"
    remote_api_headers="$scratch/remote-api.headers"
    remote_api_response="$(curl -sS -D "$remote_api_headers" -X POST -H 'Content-Type: application/json' --data '{}' "$remote_cloud_summary_url")"
    assert_http_status "$remote_api_headers" "401" "remote cloud-storage summary route"
    assert_json_content_type "$remote_api_headers" "remote cloud-storage summary route"
    assert_json_error_response "$remote_api_response" "REMOTE_API_HEADER_MISSING" "remote cloud-storage summary route"
fi

if [[ "$run_web_entries" -eq 1 ]]; then
    command -v curl >/dev/null 2>&1 || die "curl is required for web entry checks"
    admin_login_headers="$scratch/admin-login.headers"
    admin_login_response="$(curl -fsS -D "$admin_login_headers" "$admin_login_url")"
    assert_http_status "$admin_login_headers" "200" "admin login page"
    assert_html_content_type "$admin_login_headers" "admin login page"
    case "$admin_login_response" in
        *"后台登录"*name=\"username\"*) ;;
        *) die "admin login page did not contain expected form markers" ;;
    esac
    admin_console_headers="$scratch/admin-console.headers"
    curl -sS -D "$admin_console_headers" -o /dev/null "$admin_console_url"
    grep -Eq '^HTTP/[0-9.]+ 302 ' "$admin_console_headers" || die "admin console without session did not redirect"
    grep -Eiq '^location: /admin/login/?[[:space:]]*$' "$admin_console_headers" || die "admin console redirect target is not /admin/login/"
    admin_session_headers="$scratch/admin-session.headers"
    admin_session_response="$(curl -sS -D "$admin_session_headers" -X POST -H 'Content-Type: application/json' --data '{}' "$admin_session_url")"
    assert_http_status "$admin_session_headers" "401" "legacy admin session bridge"
    assert_json_content_type "$admin_session_headers" "legacy admin session bridge"
    assert_json_error_response "$admin_session_response" "ADMIN_LOGIN_REQUIRED" "legacy admin session bridge"
    static_asset_index=0
    for static_asset_url in "${static_asset_urls[@]}"; do
        static_asset_file="$scratch/static-asset-$static_asset_index"
        curl -fsS -o "$static_asset_file" "$static_asset_url" || die "static asset is not reachable: $static_asset_url"
        [[ -s "$static_asset_file" ]] || die "static asset is empty: $static_asset_url"
        assert_static_asset_content "$static_asset_url" "$static_asset_file"
        static_asset_index=$((static_asset_index + 1))
    done
fi

if [[ -n "$service_name" ]]; then
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required for service checks"
    systemctl is-active --quiet "$service_name"
fi

printf 'RELEASE_SMOKE_OK base=%s current=%s\n' "$base" "$current_path"
