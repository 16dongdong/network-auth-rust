#!/usr/bin/env bash
set -euo pipefail

base="/var/www/ace-network-auth"
serviceName="network-auth-rust"
listenAddress="127.0.0.1:18080"
owner="nginx:nginx"
rustLog="info"
unitDirectory="/etc/systemd/system"
apply=0

usage() {
    cat <<'USAGE'
Usage: install-runtime-service.sh [options]

Options:
  --base <path>          Release base path. Default: /var/www/ace-network-auth
  --service <name>       systemd service name. Default: network-auth-rust
  --listen <addr:port>   Rust listen address. Default: 127.0.0.1:18080
  --owner <user[:group]> Runtime user and group. Default: nginx:nginx
  --rust-log <value>     RUST_LOG value. Default: info
  --unit-dir <path>      systemd unit directory. Default: /etc/systemd/system
  --apply                Install unit and run systemctl daemon-reload.
  -h, --help             Show this help.

Default mode is dry-run. This script never starts or enables the service.
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

splitOwner() {
    local ownerValue="$1"
    runtimeUser="${ownerValue%%:*}"
    runtimeGroup="${ownerValue#*:}"
    if [[ "$runtimeGroup" == "$ownerValue" ]]; then
        runtimeGroup="$runtimeUser"
    fi
    [[ -n "$runtimeUser" && -n "$runtimeGroup" ]] || die "owner must be user or user:group"
}

validateIdentifier() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[A-Za-z0-9_.@-]+$ ]] || die "$label contains unsupported characters: $value"
}

validateListenAddress() {
    [[ "$listenAddress" =~ ^[0-9A-Za-z_.:-]+:[0-9]+$ ]] || die "listen address must be addr:port"
}

serviceState() {
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

renderUnit() {
    local outputFile="$1"
    cat >"$outputFile" <<UNIT
[Unit]
Description=ACE Network Auth Rust backend
Wants=network-online.target
After=network-online.target mysql.service mariadb.service

[Service]
Type=simple
User=$runtimeUser
Group=$runtimeGroup
WorkingDirectory=$base/current
Environment=RUST_LOG=$rustLog
ExecStart=$base/current/network-auth-rust serve --listen $listenAddress --config $base/current/config/local.php --public-root $base/current/public --schema $base/current/resources/install/schema.sql --install-lock $base/shared/storage/cache/install.lock
Restart=on-failure
RestartSec=3
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
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
        --rust-log)
            rustLog="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --rust-log=*)
            rustLog="${1#*=}"
            shift
            ;;
        --unit-dir)
            unitDirectory="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --unit-dir=*)
            unitDirectory="${1#*=}"
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

splitOwner "$owner"
validateIdentifier "--service" "$serviceName"
validateIdentifier "--rust-log" "$rustLog"
validateListenAddress
[[ -d "$base" ]] || die "release base not found: $base"
[[ -d "$unitDirectory" ]] || die "systemd unit directory not found: $unitDirectory"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
getent passwd "$runtimeUser" >/dev/null || die "runtime user not found: $runtimeUser"
getent group "$runtimeGroup" >/dev/null || die "runtime group not found: $runtimeGroup"

base="$(readlink -f "$base")"
unitDirectory="$(readlink -f "$unitDirectory")"
unitPath="$unitDirectory/$serviceName.service"
currentState="$(serviceState)"
[[ "$currentState" != "active" ]] || die "service is active; refusing to replace active unit: $serviceName"

scratch="$(mktemp -d)"
cleanup() {
    rm -rf "$scratch"
}
trap cleanup EXIT

unitFile="$scratch/$serviceName.service"
renderUnit "$unitFile"

if [[ "$apply" -ne 1 ]]; then
    printf 'SERVICE_UNIT_DRY_RUN unit=%s state=%s\n' "$unitPath" "$currentState"
    if [[ -f "$unitPath" ]]; then
        if cmp -s "$unitFile" "$unitPath"; then
            printf 'SERVICE_UNIT_MATCH unit=%s\n' "$unitPath"
        else
            printf 'SERVICE_UNIT_DIFF unit=%s\n' "$unitPath"
            diff -u "$unitPath" "$unitFile" || true
        fi
    else
        printf 'SERVICE_UNIT_CREATE unit=%s\n' "$unitPath"
        cat "$unitFile"
    fi
    printf 'SERVICE_UNIT_DRY_RUN_OK unit=%s\n' "$unitPath"
    exit 0
fi

printCommand install -m 0644 "$unitFile" "$unitPath"
install -m 0644 "$unitFile" "$unitPath"
printCommand systemctl daemon-reload
systemctl daemon-reload
newState="$(serviceState)"
[[ "$newState" == "inactive" ]] || die "service should be installed but inactive; actual state: $newState"
printf 'SERVICE_UNIT_INSTALL_OK unit=%s state=%s\n' "$unitPath" "$newState"
