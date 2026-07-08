#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
project_root="$(cd "$script_directory/../.." && pwd -P)"

binary_path=""
config_path=""
config_symlink_target=""
release_path=""
storage_symlink_base=""
skip_check=0

usage() {
    cat <<'USAGE'
Usage: assemble-release-package.sh --binary <path> --release <path> [options]

Options:
  --binary <path>                 Linux network-auth-rust binary to package.
  --release <path>                Output unpacked release directory. It must not already exist.
  --config <path>                 Copy a local config/local.php into the release.
  --config-symlink-target <path>  Create config/local.php as a symlink to this target.
  --storage-symlink-base <path>   Create storage runtime entries as symlinks under this shared storage base.
  --skip-check                    Assemble only; do not run release-package-check.sh.
  -h, --help                      Show this help.

Exactly one of --config or --config-symlink-target is required.
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

canonical_existing_file() {
    local path="$1"
    [[ -f "$path" ]] || die "file not found: $path"
    cd "$(dirname "$path")"
    printf '%s/%s' "$(pwd -P)" "$(basename "$path")"
}

copy_tree() {
    local source_path="$1"
    local target_path="$2"
    [[ -d "$source_path" ]] || die "source directory not found: $source_path"
    mkdir -p "$target_path"
    (
        cd "$source_path"
        tar cf - .
    ) | (
        cd "$target_path"
        tar xf -
    )
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            binary_path="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --binary=*)
            binary_path="${1#*=}"
            shift
            ;;
        --release)
            release_path="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --release=*)
            release_path="${1#*=}"
            shift
            ;;
        --config)
            config_path="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --config=*)
            config_path="${1#*=}"
            shift
            ;;
        --config-symlink-target)
            config_symlink_target="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --config-symlink-target=*)
            config_symlink_target="${1#*=}"
            shift
            ;;
        --storage-symlink-base)
            storage_symlink_base="$(need_value "$1" "${2:-}")"
            shift 2
            ;;
        --storage-symlink-base=*)
            storage_symlink_base="${1#*=}"
            shift
            ;;
        --skip-check)
            skip_check=1
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

[[ -n "$binary_path" ]] || die "--binary is required"
[[ -n "$release_path" ]] || die "--release is required"
[[ -n "$config_path" || -n "$config_symlink_target" ]] || die "one of --config or --config-symlink-target is required"
[[ -z "$config_path" || -z "$config_symlink_target" ]] || die "--config and --config-symlink-target cannot be used together"
[[ ! -e "$release_path" && ! -L "$release_path" ]] || die "release path already exists: $release_path"

binary_path="$(canonical_existing_file "$binary_path")"
if [[ -n "$config_path" ]]; then
    config_path="$(canonical_existing_file "$config_path")"
fi

release_parent="$(dirname "$release_path")"
release_name="$(basename "$release_path")"
mkdir -p "$release_parent"
release_parent="$(cd "$release_parent" && pwd -P)"
release_path="$release_parent/$release_name"
temp_path="$release_parent/.$release_name.assembling.$$"
case "$temp_path" in
    "$release_parent"/.*.assembling.*) ;;
    *) die "unsafe temporary release path: $temp_path" ;;
esac

cleanup_temp_path() {
    rm -rf "$temp_path"
}
trap cleanup_temp_path EXIT

mkdir -p "$temp_path/config"
copy_tree "$project_root/public" "$temp_path/public"
copy_tree "$project_root/resources" "$temp_path/resources"
copy_tree "$project_root/deploy" "$temp_path/deploy"
cp "$binary_path" "$temp_path/network-auth-rust"

if [[ -n "$config_path" ]]; then
    cp "$config_path" "$temp_path/config/local.php"
else
    ln -s "$config_symlink_target" "$temp_path/config/local.php"
fi

if [[ -n "$storage_symlink_base" ]]; then
    mkdir -p "$temp_path/storage"
    for directory_name in cache logs runtime-cache build cloud-storage; do
        ln -s "$storage_symlink_base/$directory_name" "$temp_path/storage/$directory_name"
    done
fi

find "$temp_path" -type d -exec chmod 755 {} +
find "$temp_path" -type f -exec chmod 644 {} +
chmod 755 "$temp_path/network-auth-rust"
find "$temp_path/deploy/scripts" -maxdepth 1 -type f -name '*.sh' -exec chmod +x {} +

if [[ "$skip_check" -eq 0 ]]; then
    package_check_args=("$temp_path/deploy/scripts/release-package-check.sh" --release "$temp_path")
    if [[ -n "$config_symlink_target" ]]; then
        package_check_args+=(--require-config-symlink)
    fi
    bash "${package_check_args[@]}"
fi

mv "$temp_path" "$release_path"
trap - EXIT
printf 'ASSEMBLE_RELEASE_PACKAGE_OK release=%s\n' "$release_path"
