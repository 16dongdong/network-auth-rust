#!/usr/bin/env bash
set -euo pipefail

release_path=""
require_config_symlink=0
runtime_storage_dirs=(cache logs runtime-cache build cloud-storage)
required_files=(
    public/install/index.html
    public/install/install.css
    public/install/disclaimer.html
    public/frontend/admin-console/index.html
    public/frontend/admin-console/css/app.css
    public/frontend/admin-console/js/app.js
    public/frontend/admin-console/js/http.js
    public/frontend/admin-console/js/state.js
    public/frontend/admin-console/js/view.js
    public/assets/layui/layui.js
    public/assets/layui/css/layui.css
    public/frontend/admin-console/js/img/brand-avatar.webp
    public/frontend/admin-console/js/img/install-complete.webp
    resources/install/schema.sql
)
required_executables=(
    network-auth-rust
    deploy/scripts/cutover-readiness-check.sh
    deploy/scripts/install-runtime-service.sh
    deploy/scripts/php-fallback-readiness-check.sh
    deploy/scripts/post-cutover-final-gate.sh
    deploy/scripts/pre-cutover-final-gate.sh
    deploy/scripts/pre-switch-release-smoke.sh
    deploy/scripts/release-smoke.sh
    deploy/scripts/rollback-to-php-release.sh
    deploy/scripts/switch-nginx-backend.sh
    deploy/scripts/switch-nginx-ssl-backend.sh
    deploy/scripts/switch-release.sh
    deploy/scripts/release-package-check.sh
)

usage() {
    cat <<'USAGE'
Usage: release-package-check.sh --release <path> [options]

Options:
  --release <path>          Unpacked Rust release directory to validate.
  --require-config-symlink  Require config/local.php to be a valid symlink.
  -h, --help                Show this help.

This check is intentionally offline: it validates release files, executable bits,
and storage packaging shape before the release is switched into production.
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

assert_regular_file() {
    local path="$1"
    [[ -f "$path" ]] || die "required file missing: $path"
    [[ ! -L "$path" ]] || die "required file must be packaged as a regular file: $path"
    [[ -s "$path" ]] || die "required file is empty: $path"
    assert_not_group_or_world_writable "$path"
}

assert_not_group_or_world_writable() {
    local path="$1"
    local mode
    local group_digit
    local other_digit
    mode="$(stat -c '%a' "$path")"
    group_digit="${mode: -2:1}"
    other_digit="${mode: -1}"
    (( (10#$group_digit & 2) == 0 )) || die "path must not be group-writable: $path"
    (( (10#$other_digit & 2) == 0 )) || die "path must not be world-writable: $path"
}

assert_file_contains() {
    local path="$1"
    local marker="$2"
    local label="$3"
    grep -Fqa -- "$marker" "$path" || die "$label content marker missing: $path"
}

assert_required_content_markers() {
    assert_file_contains "$release_path/public/assets/layui/layui.js" "layui.define" "layui.js"
    assert_file_contains "$release_path/public/frontend/admin-console/js/app.js" "(function (app)" "admin app.js"
    assert_file_contains "$release_path/public/frontend/admin-console/css/app.css" ".auth-admin" "admin app.css"
    assert_file_contains "$release_path/public/frontend/admin-console/js/img/brand-avatar.webp" "WEBP" "brand avatar"
    assert_file_contains "$release_path/public/frontend/admin-console/js/img/install-complete.webp" "WEBP" "install complete image"
}

assert_executable_file() {
    local path="$1"
    [[ -f "$path" ]] || die "required executable missing: $path"
    [[ ! -L "$path" ]] || die "required executable must be packaged as a regular file: $path"
    [[ -x "$path" ]] || die "required executable is not executable: $path"
    assert_not_group_or_world_writable "$path"
}

assert_config_file() {
    local path="$1"
    [[ -f "$path" ]] || die "config file missing: $path"
    if [[ "$require_config_symlink" -eq 1 ]]; then
        [[ -L "$path" ]] || die "config file is not a symlink: $path"
        local target_path
        target_path="$(readlink -f "$path" 2>/dev/null || true)"
        [[ -n "$target_path" && -f "$target_path" ]] || die "config symlink target is invalid: $path"
    fi
}

assert_no_packaged_runtime_storage() {
    local release_storage_dir="$1"
    local directory_name
    local storage_path

    [[ -d "$release_storage_dir" ]] || return 0
    for directory_name in "${runtime_storage_dirs[@]}"; do
        storage_path="$release_storage_dir/$directory_name"
        [[ -e "$storage_path" || -L "$storage_path" ]] || continue
        [[ -L "$storage_path" ]] || die "runtime storage must not be packaged as a directory: $storage_path"
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            release_path="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --release=*)
            release_path="${1#*=}"
            shift
            ;;
        --require-config-symlink)
            require_config_symlink=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -n "$release_path" ]] || die "--release is required"
[[ -d "$release_path" ]] || die "release directory not found: $release_path"

release_path="$(cd "$release_path" && pwd -P)"

for directory_path in \
    "$release_path" \
    "$release_path/config" \
    "$release_path/public" \
    "$release_path/resources" \
    "$release_path/deploy" \
    "$release_path/deploy/scripts"; do
    [[ -d "$directory_path" ]] || die "required directory missing: $directory_path"
    assert_not_group_or_world_writable "$directory_path"
done

assert_config_file "$release_path/config/local.php"
for relative_path in "${required_files[@]}"; do
    assert_regular_file "$release_path/$relative_path"
done
assert_required_content_markers
for relative_path in "${required_executables[@]}"; do
    assert_executable_file "$release_path/$relative_path"
done
assert_no_packaged_runtime_storage "$release_path/storage"

printf 'RELEASE_PACKAGE_CHECK_OK release=%s\n' "$release_path"
