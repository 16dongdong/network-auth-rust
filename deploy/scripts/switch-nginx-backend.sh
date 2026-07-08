#!/usr/bin/env bash
set -euo pipefail

mode=""
configPath=""
backupPath=""
listenAddress="127.0.0.1:18080"
clientMaxBodySize="1024m"
apply=0
reloadNginx=1

usage() {
    cat <<'USAGE'
Usage: switch-nginx-backend.sh --mode <rust|php> --config <path> [options]

Options:
  --mode <rust|php>              Target Nginx backend mode.
  --config <path>                Nginx site config file to replace.
  --backup <path>                PHP config backup path. Default: <config>.php-backup
  --listen <addr:port>           Rust upstream listen address. Default: 127.0.0.1:18080
  --client-max-body-size <value> Rust proxy client_max_body_size. Default: 1024m
  --skip-reload                  Do not reload Nginx after applying.
  --apply                        Actually replace config, run nginx -t, and reload Nginx.
  -h, --help                     Show this help.

Default mode is dry-run. The script does not change current or systemd.
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

validateListenAddress() {
    [[ "$listenAddress" =~ ^[0-9A-Za-z_.:-]+:[0-9]+$ ]] || die "listen address must be addr:port"
}

validateClientMaxBodySize() {
    [[ "$clientMaxBodySize" =~ ^[0-9]+[kKmMgG]?$ ]] || die "invalid client_max_body_size: $clientMaxBodySize"
}

extractFirstLine() {
    local pattern="$1"
    local sourceFile="$2"
    grep -E "$pattern" "$sourceFile" | head -1 | sed -E 's/^[[:space:]]+//'
}

extractListenLines() {
    local sourceFile="$1"
    grep -E '^[[:space:]]*listen[[:space:]]+' "$sourceFile" | sed -E 's/^[[:space:]]+//' || true
}

assertSingleServerBlock() {
    local sourceFile="$1"
    local serverCount
    serverCount="$(grep -Ec '^[[:space:]]*server[[:space:]]*\{' "$sourceFile" || true)"
    [[ "$serverCount" -eq 1 ]] || die "expected exactly one server block in $sourceFile, found $serverCount"
}

renderRustConfig() {
    local sourceFile="$1"
    local outputFile="$2"
    local listenLines
    local serverNameLine
    local accessLogLine
    local errorLogLine

    listenLines="$(extractListenLines "$sourceFile")"
    serverNameLine="$(extractFirstLine '^[[:space:]]*server_name[[:space:]]+' "$sourceFile")"
    accessLogLine="$(extractFirstLine '^[[:space:]]*access_log[[:space:]]+' "$sourceFile")"
    errorLogLine="$(extractFirstLine '^[[:space:]]*error_log[[:space:]]+' "$sourceFile")"

    [[ -n "$listenLines" ]] || die "cannot find listen directive in $sourceFile"
    [[ -n "$serverNameLine" ]] || die "cannot find server_name directive in $sourceFile"

    {
        printf 'server {\n'
        while IFS= read -r listenLine; do
            [[ -n "$listenLine" ]] && printf '    %s\n' "$listenLine"
        done <<<"$listenLines"
        printf '    %s\n' "$serverNameLine"
        if [[ -n "$accessLogLine" ]]; then
            printf '    %s\n' "$accessLogLine"
        fi
        if [[ -n "$errorLogLine" ]]; then
            printf '    %s\n' "$errorLogLine"
        fi
        cat <<RUST_CONF
    client_max_body_size $clientMaxBodySize;

    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 5;
    gzip_types text/css application/javascript application/json image/svg+xml text/plain;

    location / {
        proxy_pass http://$listenAddress;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }

    location ~ /\. {
        deny all;
    }
}
RUST_CONF
    } >"$outputFile"
}

showDiff() {
    local fromFile="$1"
    local toFile="$2"
    if cmp -s "$fromFile" "$toFile"; then
        printf 'NGINX_BACKEND_CONFIG_MATCH config=%s\n' "$configPath"
        return
    fi
    diff -u "$fromFile" "$toFile" || true
}

reloadNginxService() {
    local mainPid
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx; then
        mainPid="$(systemctl show nginx --property MainPID --value 2>/dev/null || true)"
        if [[ "$mainPid" =~ ^[0-9]+$ && "$mainPid" -gt 1 ]]; then
            printCommand kill -HUP "$mainPid"
            kill -HUP "$mainPid"
            return
        fi
    fi
    printCommand nginx -s reload
    nginx -s reload
}

applyConfig() {
    local targetFile="$1"
    local previousFile="$scratch/previous.conf"
    local tempFile
    tempFile="$(mktemp "$(dirname "$configPath")/.nginx-backend.XXXXXX")"
    cp "$configPath" "$previousFile"
    install -m 0644 "$targetFile" "$tempFile"
    if [[ "$mode" == "rust" && ! -f "$backupPath" ]]; then
        printCommand cp "$configPath" "$backupPath"
        cp "$configPath" "$backupPath"
    fi
    printCommand mv -f "$tempFile" "$configPath"
    mv -f "$tempFile" "$configPath"
    if ! nginx -t; then
        printf 'ERROR: nginx config test failed; restoring previous config\n' >&2
        cp "$previousFile" "$configPath"
        nginx -t >/dev/null 2>&1 || true
        exit 1
    fi
    if [[ "$reloadNginx" -eq 1 ]]; then
        reloadNginxService
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            mode="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --mode=*)
            mode="${1#*=}"
            shift
            ;;
        --config)
            configPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --config=*)
            configPath="${1#*=}"
            shift
            ;;
        --backup)
            backupPath="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --backup=*)
            backupPath="${1#*=}"
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
        --client-max-body-size)
            clientMaxBodySize="$(needValue "$1" "${2:-}")"
            shift 2
            ;;
        --client-max-body-size=*)
            clientMaxBodySize="${1#*=}"
            shift
            ;;
        --skip-reload)
            reloadNginx=0
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

[[ "$mode" == "rust" || "$mode" == "php" ]] || die "--mode must be rust or php"
[[ -n "$configPath" ]] || die "--config is required"
[[ -f "$configPath" ]] || die "config file not found: $configPath"
assertSingleServerBlock "$configPath"
if [[ -z "$backupPath" ]]; then
    backupPath="$configPath.php-backup"
fi
validateListenAddress
validateClientMaxBodySize
command -v nginx >/dev/null 2>&1 || die "nginx command is required"

scratch="$(mktemp -d)"
cleanup() {
    rm -rf "$scratch"
}
trap cleanup EXIT

targetConfig="$scratch/target.conf"
if [[ "$mode" == "rust" ]]; then
    renderRustConfig "$configPath" "$targetConfig"
else
    [[ -f "$backupPath" ]] || die "PHP backup config not found: $backupPath"
    cp "$backupPath" "$targetConfig"
fi

if [[ "$apply" -ne 1 ]]; then
    printf 'NGINX_BACKEND_DRY_RUN mode=%s config=%s backup=%s\n' "$mode" "$configPath" "$backupPath"
    showDiff "$configPath" "$targetConfig"
    printf 'NGINX_BACKEND_DRY_RUN_OK mode=%s config=%s\n' "$mode" "$configPath"
    exit 0
fi

applyConfig "$targetConfig"
printf 'NGINX_BACKEND_SWITCH_OK mode=%s config=%s backup=%s\n' "$mode" "$configPath" "$backupPath"
