#!/usr/bin/env bash
set -euo pipefail

scriptDirectory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
releaseSmokeScript="$scriptDirectory/release-smoke.sh"
cutoverReadinessCheckScript="$scriptDirectory/cutover-readiness-check.sh"
installRuntimeServiceScript="$scriptDirectory/install-runtime-service.sh"
phpFallbackReadinessCheckScript="$scriptDirectory/php-fallback-readiness-check.sh"
postCutoverFinalGateScript="$scriptDirectory/post-cutover-final-gate.sh"
preCutoverFinalGateScript="$scriptDirectory/pre-cutover-final-gate.sh"
preSwitchReleaseSmokeScript="$scriptDirectory/pre-switch-release-smoke.sh"
rollbackToPhpReleaseScript="$scriptDirectory/rollback-to-php-release.sh"
switchNginxBackendScript="$scriptDirectory/switch-nginx-backend.sh"
switchNginxSslBackendScript="$scriptDirectory/switch-nginx-ssl-backend.sh"
switchReleaseScript="$scriptDirectory/switch-release.sh"
releasePackageCheckScript="$scriptDirectory/release-package-check.sh"
assembleReleasePackageScript="$scriptDirectory/assemble-release-package.sh"
workRoot=""

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    [[ -n "$workRoot" ]] || return 0
    case "$workRoot" in
        /tmp/*) rm -rf "$workRoot" ;;
        *) printf 'Refuse to remove unexpected path: %s\n' "$workRoot" >&2 ;;
    esac
}

assertCurrentRelease() {
    local releaseBase="$1"
    local expectedRelease="$2"
    local actualPath
    local expectedPath
    actualPath="$(readlink -f "$releaseBase/current")"
    expectedPath="$(readlink -f "$releaseBase/releases/$expectedRelease")"
    [[ "$actualPath" == "$expectedPath" ]] || die "current points to $actualPath, expected $expectedPath"
}

assertOutputContains() {
    local outputFile="$1"
    local expectedText="$2"
    grep -Fq "$expectedText" "$outputFile" || die "expected output to contain: $expectedText"
}

assertOutputNotContains() {
    local outputFile="$1"
    local unexpectedText="$2"
    if grep -Fq "$unexpectedText" "$outputFile"; then
        die "unexpected output contains: $unexpectedText"
    fi
}

replaceCurrentLink() {
    local releaseBase="$1"
    local targetPath="$2"
    rm -f "$releaseBase/current"
    ln -s "$targetPath" "$releaseBase/current"
}

writeFakeBinary() {
    local binaryPath="$1"
    cat >"$binaryPath" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

commandName="${1:-}"
shift || true
releaseBase=""
runtimeOwner=""
keepCount="3"
dryRun=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            releaseBase="${2:-}"
            shift 2
            ;;
        --base=*)
            releaseBase="${1#*=}"
            shift
            ;;
        --owner)
            runtimeOwner="${2:-}"
            shift 2
            ;;
        --owner=*)
            runtimeOwner="${1#*=}"
            shift
            ;;
        --keep)
            keepCount="${2:-}"
            shift 2
            ;;
        --keep=*)
            keepCount="${1#*=}"
            shift
            ;;
        --dry-run)
            dryRun=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

currentPath=""
if [[ -n "$releaseBase" && -L "$releaseBase/current" ]]; then
    currentPath="$(readlink -f "$releaseBase/current")"
fi

case "$commandName" in
    prepare-release-storage)
        printf '{\n'
        printf '  "base": "%s",\n' "$releaseBase"
        printf '  "current": "%s",\n' "$currentPath"
        printf '  "owner": "%s",\n' "$runtimeOwner"
        printf '  "dryRun": %s,\n' "$dryRun"
        printf '  "prepared": []\n'
        printf '}\n'
        ;;
    prune-releases)
        if [[ "${FAKE_BINARY_PRUNE_FAIL:-0}" == "1" && "$dryRun" == "false" ]]; then
            printf 'fake prune failure\n' >&2
            exit 44
        fi
        printf '{\n'
        printf '  "base": "%s",\n' "$releaseBase"
        printf '  "current": "%s",\n' "$currentPath"
        printf '  "keepCount": %s,\n' "$keepCount"
        printf '  "removedCount": 0,\n'
        printf '  "dryRun": %s,\n' "$dryRun"
        printf '  "kept": [],\n'
        printf '  "removed": []\n'
        printf '}\n'
        ;;
    preflight)
        printf 'FAKE_PREFLIGHT_OK\n'
        ;;
    *)
        printf 'unsupported fake binary command: %s\n' "$commandName" >&2
        exit 2
        ;;
esac
STUB
    chmod +x "$binaryPath"
}

writeFakePhp() {
    local phpPath="$1"
    local fakeBinary="$2"
    cat >"$phpPath" <<STUB
#!/usr/bin/env bash
set -euo pipefail
scriptPath="\${1:-}"
shift || true
case "\$(basename "\$scriptPath")" in
    prepareReleaseStorage.php)
        exec "$fakeBinary" prepare-release-storage "\$@"
        ;;
    pruneReleases.php)
        exec "$fakeBinary" prune-releases "\$@"
        ;;
    *)
        printf 'unsupported fake PHP script: %s\n' "\$scriptPath" >&2
        exit 2
        ;;
esac
STUB
    chmod +x "$phpPath"
}

writeFakeCurl() {
    local curlPath="$1"
    cat >"$curlPath" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

method="GET"
url=""
headerFile=""
outputFile=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -X)
            method="${2:-}"
            shift 2
            ;;
        -D)
            headerFile="${2:-}"
            shift 2
            ;;
        -o)
            outputFile="${2:-}"
            shift 2
            ;;
        -H|--data|--data-raw|--data-binary)
            shift 2
            ;;
        -fsS|-f|-s|-S)
            shift
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done

if [[ -n "${FAKE_CURL_LOG:-}" ]]; then
    printf '%s %s\n' "$method" "$url" >>"$FAKE_CURL_LOG"
fi

emitBody() {
    local body="$1"
    if [[ -n "$outputFile" && "$outputFile" != "/dev/null" ]]; then
        printf '%s' "$body" >"$outputFile"
    else
        printf '%s' "$body"
    fi
}

emitStaticAsset() {
    local body
    if [[ ${FAKE_CURL_STATIC_BODY+x} ]]; then
        emitBody "$FAKE_CURL_STATIC_BODY"
        return
    fi
    case "$url" in
        */assets/layui/layui.js)
            body='/** v2.13.7 | MIT Licensed */ layui.define(function(){});'
            ;;
        */frontend/admin-console/js/app.js)
            body='(function (app) { app.smoke = true; })(window.app || {});'
            ;;
        */frontend/admin-console/css/app.css)
            body='.auth-admin { display: block; }'
            ;;
        */frontend/admin-console/js/img/brand-avatar.webp)
            body='RIFF0000WEBP'
            ;;
        *)
            body='asset-body'
            ;;
    esac
    emitBody "$body"
}

writeJsonHeaders() {
    [[ -n "$headerFile" ]] || return 0
    {
        printf 'HTTP/1.1 %s\r\n' "${FAKE_CURL_JSON_STATUS:-401 Unauthorized}"
        printf 'content-type: %s\r\n' "${FAKE_CURL_JSON_CONTENT_TYPE:-application/json; charset=utf-8}"
        printf '\r\n'
    } >"$headerFile"
}

writeAdminLoginHeaders() {
    [[ -n "$headerFile" ]] || return 0
    {
        printf 'HTTP/1.1 %s\r\n' "${FAKE_CURL_ADMIN_LOGIN_STATUS:-200 OK}"
        printf 'content-type: %s\r\n' "${FAKE_CURL_ADMIN_LOGIN_CONTENT_TYPE:-text/html; charset=utf-8}"
        printf '\r\n'
    } >"$headerFile"
}

writeHealthHeaders() {
    [[ -n "$headerFile" ]] || return 0
    local contentType
    contentType="${FAKE_CURL_HEALTH_CONTENT_TYPE:-application/json; charset=utf-8}"
    if [[ "$url" == *public.example.test* ]]; then
        contentType="${FAKE_CURL_PUBLIC_HEALTH_CONTENT_TYPE:-$contentType}"
    fi
    {
        printf 'HTTP/1.1 200 OK\r\n'
        printf 'content-type: %s\r\n' "$contentType"
        printf '\r\n'
    } >"$headerFile"
}

case "$url" in
    */health)
        writeHealthHeaders
        if [[ "$url" == *public.example.test* ]]; then
            emitBody "${FAKE_CURL_PUBLIC_HEALTH_BODY:-{\"code\":0,\"data\":{\"runtime\":\"rust\"}}}"
        else
            emitBody "${FAKE_CURL_HEALTH_BODY:-{\"code\":0,\"data\":{\"runtime\":\"rust\"}}}"
        fi
        ;;
    *remote%2Fcloud-storage%2Fsummary*|*/remote/cloud-storage/summary*)
        writeJsonHeaders
        emitBody "${FAKE_CURL_REMOTE_API_BODY:-{\"code\":401,\"error\":\"REMOTE_API_HEADER_MISSING\",\"message\":\"REMOTE_API_HEADER_MISSING\"}}"
        ;;
    */sub_admin/admin_session.php)
        writeJsonHeaders
        emitBody "${FAKE_CURL_ADMIN_SESSION_BODY:-{\"code\":401,\"error\":\"ADMIN_LOGIN_REQUIRED\",\"message\":\"ADMIN_LOGIN_REQUIRED\"}}"
        ;;
    */admin/login/*)
        writeAdminLoginHeaders
        emitBody '<!doctype html><title>后台登录</title><input name="username">'
        ;;
    */admin/console/*)
        if [[ -n "$headerFile" ]]; then
            {
                printf 'HTTP/1.1 302 Found\r\n'
                printf 'location: %s\r\n' "${FAKE_CURL_ADMIN_CONSOLE_LOCATION:-/admin/login/}"
                printf '\r\n'
            } >"$headerFile"
        fi
        if [[ -n "$outputFile" && "$outputFile" != "/dev/null" ]]; then
            : >"$outputFile"
        fi
        ;;
    */assets/layui/layui.js|*/frontend/admin-console/js/app.js|*/frontend/admin-console/css/app.css|*/frontend/admin-console/js/img/brand-avatar.webp)
        emitStaticAsset
        ;;
    *)
        ;;
esac
STUB
    chmod +x "$curlPath"
}

writeFakeNginx() {
    local nginxPath="$1"
    cat >"$nginxPath" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${FAKE_NGINX_LOG:-}" ]]; then
    printf 'nginx %s\n' "$*" >>"$FAKE_NGINX_LOG"
fi

case "${1:-}" in
    -t)
        exit 0
        ;;
    -s)
        [[ "${2:-}" == "reload" ]] || exit 2
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
STUB
    chmod +x "$nginxPath"
}

writeFakeSystemctl() {
    local systemctlPath="$1"
    cat >"$systemctlPath" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
    cat)
        cat "${FAKE_SYSTEMD_UNIT:?FAKE_SYSTEMD_UNIT is required}"
        ;;
    is-active)
        if [[ "${2:-}" == "--quiet" ]]; then
            [[ "${FAKE_SYSTEMD_STATE:-inactive}" == "active" ]]
            exit $?
        fi
        printf '%s\n' "${FAKE_SYSTEMD_STATE:-inactive}"
        [[ "${FAKE_SYSTEMD_STATE:-inactive}" == "active" ]]
        ;;
    *)
        exit 0
        ;;
esac
STUB
    chmod +x "$systemctlPath"
}

writeReleasePackageFiles() {
    local releasePath="$1"
    local requiredFile
    local requiredFiles=(
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

    for requiredFile in "${requiredFiles[@]}"; do
        mkdir -p "$(dirname "$releasePath/$requiredFile")"
        case "$requiredFile" in
            public/assets/layui/layui.js)
                printf '/** layui fixture */ layui.define(function(){});\n' >"$releasePath/$requiredFile"
                ;;
            public/frontend/admin-console/js/app.js)
                printf '(function (app) { app.fixture = true; })(window.app || {});\n' >"$releasePath/$requiredFile"
                ;;
            public/frontend/admin-console/css/app.css)
                printf '.auth-admin { display: block; }\n' >"$releasePath/$requiredFile"
                ;;
            public/frontend/admin-console/js/img/brand-avatar.webp|public/frontend/admin-console/js/img/install-complete.webp)
                printf 'RIFF0000WEBP\n' >"$releasePath/$requiredFile"
                ;;
            *)
                printf 'package fixture: %s\n' "$requiredFile" >"$releasePath/$requiredFile"
                ;;
        esac
    done
}

createRelease() {
    local releaseBase="$1"
    local releaseName="$2"
    local smokeMode="$3"
    local releasePath="$releaseBase/releases/$releaseName"
    mkdir -p "$releasePath/config" "$releasePath/deploy/scripts" "$releasePath/public" "$releasePath/resources/install" "$releasePath/storage"
    printf '<?php\n' >"$releasePath/config/local.php"
    writeReleasePackageFiles "$releasePath"
    writeFakeBinary "$releasePath/network-auth-rust"
    for directoryName in cache logs runtime-cache build cloud-storage; do
        ln -s "$releaseBase/shared/storage/$directoryName" "$releasePath/storage/$directoryName"
    done
    if [[ "$smokeMode" == "pass" ]]; then
        cp "$releaseSmokeScript" "$releasePath/deploy/scripts/release-smoke.sh"
    else
        cat >"$releasePath/deploy/scripts/release-smoke.sh" <<'SMOKE'
#!/usr/bin/env bash
exit 42
SMOKE
    fi
    cp "$cutoverReadinessCheckScript" "$releasePath/deploy/scripts/cutover-readiness-check.sh"
    cp "$installRuntimeServiceScript" "$releasePath/deploy/scripts/install-runtime-service.sh"
    cp "$phpFallbackReadinessCheckScript" "$releasePath/deploy/scripts/php-fallback-readiness-check.sh"
    cp "$postCutoverFinalGateScript" "$releasePath/deploy/scripts/post-cutover-final-gate.sh"
    cp "$preCutoverFinalGateScript" "$releasePath/deploy/scripts/pre-cutover-final-gate.sh"
    cp "$preSwitchReleaseSmokeScript" "$releasePath/deploy/scripts/pre-switch-release-smoke.sh"
    cp "$rollbackToPhpReleaseScript" "$releasePath/deploy/scripts/rollback-to-php-release.sh"
    cp "$switchNginxBackendScript" "$releasePath/deploy/scripts/switch-nginx-backend.sh"
    cp "$switchNginxSslBackendScript" "$releasePath/deploy/scripts/switch-nginx-ssl-backend.sh"
    cp "$switchReleaseScript" "$releasePath/deploy/scripts/switch-release.sh"
    cp "$releasePackageCheckScript" "$releasePath/deploy/scripts/release-package-check.sh"
    chmod +x "$releasePath/deploy/scripts/cutover-readiness-check.sh" "$releasePath/deploy/scripts/install-runtime-service.sh" "$releasePath/deploy/scripts/php-fallback-readiness-check.sh" "$releasePath/deploy/scripts/post-cutover-final-gate.sh" "$releasePath/deploy/scripts/pre-cutover-final-gate.sh" "$releasePath/deploy/scripts/pre-switch-release-smoke.sh" "$releasePath/deploy/scripts/release-smoke.sh" "$releasePath/deploy/scripts/rollback-to-php-release.sh" "$releasePath/deploy/scripts/switch-nginx-backend.sh" "$releasePath/deploy/scripts/switch-nginx-ssl-backend.sh" "$releasePath/deploy/scripts/switch-release.sh" "$releasePath/deploy/scripts/release-package-check.sh"
}

createPhpRelease() {
    local releaseBase="$1"
    local releaseName="$2"
    local releasePath="$releaseBase/releases/$releaseName"
    mkdir -p "$releasePath/config" "$releasePath/public" "$releasePath/storage"
    printf '<?php echo "php release";\n' >"$releasePath/index.php"
    printf 'php public fixture\n' >"$releasePath/public/index.html"
    printf '<?php return ["php" => true];\n' >"$releasePath/config/local.php"
    for directoryName in cache logs runtime-cache build cloud-storage; do
        ln -s "$releaseBase/shared/storage/$directoryName" "$releasePath/storage/$directoryName"
    done
}

prepareFixture() {
    workRoot="$(mktemp -d)"
    trap cleanup EXIT
    releaseBase="$workRoot/ace-network-auth"
    mkdir -p "$releaseBase/releases" "$releaseBase/shared/config" "$releaseBase/shared/storage"
    printf '<?php\n' >"$releaseBase/shared/config/local.php"
    for directoryName in cache logs runtime-cache build cloud-storage; do
        mkdir -p "$releaseBase/shared/storage/$directoryName"
    done
    createRelease "$releaseBase" old pass
    createRelease "$releaseBase" new pass
    createRelease "$releaseBase" fail fail
    createPhpRelease "$releaseBase" php-old
    ln -s "$releaseBase/releases/old" "$releaseBase/current"
    phpToolsRoot="$workRoot/php-tools"
    mkdir -p "$phpToolsRoot/tools/scripts"
    touch "$phpToolsRoot/tools/scripts/prepareReleaseStorage.php" "$phpToolsRoot/tools/scripts/pruneReleases.php"
    fakePhp="$workRoot/fakePhp"
    writeFakePhp "$fakePhp" "$releaseBase/releases/old/network-auth-rust"
}

runReleaseSmokeSelfTest() {
    local outputFile="$workRoot/releaseSmoke.out"
    "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --keep 3 \
        --php-bin "$fakePhp" \
        --php-tools-root "$phpToolsRoot" \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_SMOKE_OK"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageCheckSelfTest() {
    local outputFile="$workRoot/releasePackageCheck.out"
    "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectLocalStorageSelfTest() {
    local outputFile="$workRoot/releasePackageLocalStorage.out"
    local errorFile="$workRoot/releasePackageLocalStorage.err"
    local storagePath="$releaseBase/releases/new/storage/cache"
    rm "$storagePath"
    mkdir "$storagePath"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted packaged runtime storage"
    fi
    assertOutputContains "$errorFile" "runtime storage must not be packaged as a directory"
    rmdir "$storagePath"
    ln -s "$releaseBase/shared/storage/cache" "$storagePath"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectWritableDirectorySelfTest() {
    local outputFile="$workRoot/releasePackageWritableDirectory.out"
    local errorFile="$workRoot/releasePackageWritableDirectory.err"
    chmod 777 "$releaseBase/releases/new"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted a writable release directory"
    fi
    assertOutputContains "$errorFile" "path must not be group-writable"
    chmod 755 "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectEmptyFileSelfTest() {
    local outputFile="$workRoot/releasePackageEmptyFile.out"
    local errorFile="$workRoot/releasePackageEmptyFile.err"
    local requiredFile="$releaseBase/releases/new/public/frontend/admin-console/js/state.js"
    : >"$requiredFile"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted an empty required file"
    fi
    assertOutputContains "$errorFile" "required file is empty"
    printf 'package fixture: public/frontend/admin-console/js/state.js\n' >"$requiredFile"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectWrongStaticMarkerSelfTest() {
    local outputFile="$workRoot/releasePackageWrongStaticMarker.out"
    local errorFile="$workRoot/releasePackageWrongStaticMarker.err"
    local appScript="$releaseBase/releases/new/public/frontend/admin-console/js/app.js"
    printf 'console.log("wrong app bundle");\n' >"$appScript"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted an invalid admin app.js marker"
    fi
    assertOutputContains "$errorFile" "admin app.js content marker missing"
    printf '(function (app) { app.fixture = true; })(window.app || {});\n' >"$appScript"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectSymlinkedRequiredFileSelfTest() {
    local outputFile="$workRoot/releasePackageSymlinkedRequiredFile.out"
    local errorFile="$workRoot/releasePackageSymlinkedRequiredFile.err"
    local requiredFile="$releaseBase/releases/new/public/frontend/admin-console/js/state.js"
    local externalFile="$workRoot/external-state.js"
    printf 'external fixture\n' >"$externalFile"
    rm "$requiredFile"
    ln -s "$externalFile" "$requiredFile"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted a symlinked required file"
    fi
    assertOutputContains "$errorFile" "required file must be packaged as a regular file"
    rm "$requiredFile"
    printf 'package fixture: public/frontend/admin-console/js/state.js\n' >"$requiredFile"
    assertCurrentRelease "$releaseBase" old
}

runReleasePackageRejectSymlinkedExecutableSelfTest() {
    local outputFile="$workRoot/releasePackageSymlinkedExecutable.out"
    local errorFile="$workRoot/releasePackageSymlinkedExecutable.err"
    local executablePath="$releaseBase/releases/new/deploy/scripts/switch-release.sh"
    local externalExecutable="$workRoot/external-switch-release.sh"
    cp "$switchReleaseScript" "$externalExecutable"
    chmod +x "$externalExecutable"
    rm "$executablePath"
    ln -s "$externalExecutable" "$executablePath"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted a symlinked executable"
    fi
    assertOutputContains "$errorFile" "required executable must be packaged as a regular file"
    rm "$executablePath"
    cp "$switchReleaseScript" "$executablePath"
    chmod +x "$executablePath"
    assertCurrentRelease "$releaseBase" old
}

runAssembleReleasePackageSelfTest() {
    local workDirectory="$workRoot/assemblePackage"
    local releasePath="$workDirectory/releases/assembled"
    local symlinkReleasePath="$workDirectory/releases/assembled-symlink"
    local binaryPath="$workDirectory/network-auth-rust"
    local configPath="$workDirectory/local.php"
    local sharedConfigPath="$workDirectory/shared/local.php"
    local sharedStoragePath="$workDirectory/shared/storage"
    local outputFile="$workDirectory/output.txt"
    mkdir -p "$workDirectory/shared"
    for directoryName in cache logs runtime-cache build cloud-storage; do
        mkdir -p "$sharedStoragePath/$directoryName"
    done
    printf '#!/usr/bin/env bash\nprintf "fake rust binary\\n"\n' >"$binaryPath"
    chmod +x "$binaryPath"
    printf '<?php return [];\n' >"$configPath"
    printf '<?php return ["shared" => true];\n' >"$sharedConfigPath"

    bash "$assembleReleasePackageScript" \
        --binary "$binaryPath" \
        --config "$configPath" \
        --release "$releasePath" >"$outputFile"

    assertOutputContains "$outputFile" "ASSEMBLE_RELEASE_PACKAGE_OK"
    bash "$releasePath/deploy/scripts/release-package-check.sh" --release "$releasePath" >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"

    bash "$assembleReleasePackageScript" \
        --binary "$binaryPath" \
        --config-symlink-target "$sharedConfigPath" \
        --storage-symlink-base "$sharedStoragePath" \
        --release "$symlinkReleasePath" >"$outputFile"

    assertOutputContains "$outputFile" "ASSEMBLE_RELEASE_PACKAGE_OK"
    bash "$symlinkReleasePath/deploy/scripts/release-package-check.sh" \
        --release "$symlinkReleasePath" \
        --require-config-symlink >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"
    [[ "$(readlink -f "$symlinkReleasePath/storage/cache")" == "$(readlink -f "$sharedStoragePath/cache")" ]] || die "assembled release storage did not point to shared storage"
}

runReleasePackageRequireConfigSymlinkSelfTest() {
    local outputFile="$workRoot/releasePackageConfigSymlink.out"
    local errorFile="$workRoot/releasePackageConfigSymlink.err"
    local targetConfigPath="$releaseBase/releases/new/config/local.php"
    local sharedConfigPath="$releaseBase/shared/config/local.php"
    if "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" \
        --require-config-symlink >"$outputFile" 2>"$errorFile"; then
        die "release-package-check accepted a regular config file when config symlink is required"
    fi
    assertOutputContains "$errorFile" "config file is not a symlink"
    rm "$targetConfigPath"
    ln -s "$sharedConfigPath" "$targetConfigPath"
    "$releasePackageCheckScript" \
        --release "$releaseBase/releases/new" \
        --require-config-symlink >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"
    rm "$targetConfigPath"
    printf '<?php\n' >"$targetConfigPath"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRequireConfigSymlinkSelfTest() {
    local outputFile="$workRoot/releaseSmokeConfigSymlink.out"
    local errorFile="$workRoot/releaseSmokeConfigSymlink.err"
    local configPath="$releaseBase/releases/old/config/local.php"
    local sharedConfigPath="$releaseBase/shared/config/local.php"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --require-config-symlink \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a regular config file when config symlink is required"
    fi
    assertOutputContains "$errorFile" "config file is not a symlink"
    rm "$configPath"
    ln -s "$sharedConfigPath" "$configPath"
    "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --require-config-symlink \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_SMOKE_OK"
    rm "$configPath"
    printf '<?php\n' >"$configPath"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRemoteApiSelfTest() {
    local outputFile="$workRoot/releaseSmokeRemote.out"
    local curlLog="$workRoot/fakeCurl.log"
    writeFakeCurl "$workRoot/curl"
    FAKE_CURL_LOG="$curlLog" PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --keep 3 \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_SMOKE_OK"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/health"
    assertOutputContains "$curlLog" "POST http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/admin/login/"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/admin/console/"
    assertOutputContains "$curlLog" "POST http://127.0.0.1:18080/sub_admin/admin_session.php"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/assets/layui/layui.js"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/frontend/admin-console/js/app.js"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/frontend/admin-console/css/app.css"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/frontend/admin-console/js/img/brand-avatar.webp"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectNonRustHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeNonRustHealth.out"
    local errorFile="$workRoot/releaseSmokeNonRustHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='{"code":0,"data":{"status":"ok"}}' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-Rust health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not report Rust runtime"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectMisleadingLocalHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeMisleadingLocalHealth.out"
    local errorFile="$workRoot/releaseSmokeMisleadingLocalHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='{"code":0,"data":{"runtime":"php","note":"rust migration ready"}}' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a misleading local health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not report Rust runtime"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectHtmlLocalHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeHtmlLocalHealth.out"
    local errorFile="$workRoot/releaseSmokeHtmlLocalHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='<!doctype html><pre>{"runtime":"rust"}</pre>' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted an HTML local health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not return a JSON object"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongLocalHealthContentTypeSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongLocalHealthContentType.out"
    local errorFile="$workRoot/releaseSmokeWrongLocalHealthContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_CONTENT_TYPE='text/html' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-JSON local health content type"
    fi
    assertOutputContains "$errorFile" "local health URL did not return JSON content type"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectNonRustPublicHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeNonRustPublicHealth.out"
    local errorFile="$workRoot/releaseSmokeNonRustPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='{"code":0,"data":{"status":"ok"}}' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-Rust public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not report Rust runtime"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectMisleadingPublicHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeMisleadingPublicHealth.out"
    local errorFile="$workRoot/releaseSmokeMisleadingPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='{"code":0,"data":{"runtime":"php","note":"rust migration ready"}}' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a misleading public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not report Rust runtime"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectHtmlPublicHealthSelfTest() {
    local outputFile="$workRoot/releaseSmokeHtmlPublicHealth.out"
    local errorFile="$workRoot/releaseSmokeHtmlPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='<!doctype html><pre>{"runtime":"rust"}</pre>' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted an HTML public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not return a JSON object"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongPublicHealthContentTypeSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongPublicHealthContentType.out"
    local errorFile="$workRoot/releaseSmokeWrongPublicHealthContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_CONTENT_TYPE='text/html' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-JSON public health content type"
    fi
    assertOutputContains "$errorFile" "public health URL did not return JSON content type"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectNonJsonRemoteApiSelfTest() {
    local outputFile="$workRoot/releaseSmokeNonJsonRemoteApi.out"
    local errorFile="$workRoot/releaseSmokeNonJsonRemoteApi.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_REMOTE_API_BODY='<html>REMOTE_API_HEADER_MISSING</html>' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-JSON remote API response"
    fi
    assertOutputContains "$errorFile" "remote cloud-storage summary route did not return a JSON object"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectNonJsonAdminSessionSelfTest() {
    local outputFile="$workRoot/releaseSmokeNonJsonAdminSession.out"
    local errorFile="$workRoot/releaseSmokeNonJsonAdminSession.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_ADMIN_SESSION_BODY='<html>ADMIN_LOGIN_REQUIRED</html>' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-JSON admin session response"
    fi
    assertOutputContains "$errorFile" "legacy admin session bridge did not return a JSON object"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongJsonContentTypeSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongJsonContentType.out"
    local errorFile="$workRoot/releaseSmokeWrongJsonContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_JSON_CONTENT_TYPE='text/html' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-JSON remote API content type"
    fi
    assertOutputContains "$errorFile" "remote cloud-storage summary route did not return JSON content type"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongJsonStatusSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongJsonStatus.out"
    local errorFile="$workRoot/releaseSmokeWrongJsonStatus.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_JSON_STATUS='200 OK' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-401 remote API response"
    fi
    assertOutputContains "$errorFile" "remote cloud-storage summary route did not return HTTP 401"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongAdminLoginStatusSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongAdminLoginStatus.out"
    local errorFile="$workRoot/releaseSmokeWrongAdminLoginStatus.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_ADMIN_LOGIN_STATUS='204 No Content' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-200 admin login response"
    fi
    assertOutputContains "$errorFile" "admin login page did not return HTTP 200"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongAdminLoginContentTypeSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongAdminLoginContentType.out"
    local errorFile="$workRoot/releaseSmokeWrongAdminLoginContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_ADMIN_LOGIN_CONTENT_TYPE='application/json' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a non-HTML admin login response"
    fi
    assertOutputContains "$errorFile" "admin login page did not return HTML content type"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectEmptyStaticAssetSelfTest() {
    local outputFile="$workRoot/releaseSmokeEmptyStatic.out"
    local errorFile="$workRoot/releaseSmokeEmptyStatic.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_STATIC_BODY='' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted an empty static asset response"
    fi
    assertOutputContains "$errorFile" "static asset is empty"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongStaticAssetSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongStatic.out"
    local errorFile="$workRoot/releaseSmokeWrongStatic.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_STATIC_BODY='<!doctype html><title>wrong asset</title>' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted an invalid static asset response"
    fi
    assertOutputContains "$errorFile" "static asset content marker missing"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeRejectWrongConsoleRedirectSelfTest() {
    local outputFile="$workRoot/releaseSmokeWrongConsoleRedirect.out"
    local errorFile="$workRoot/releaseSmokeWrongConsoleRedirect.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_ADMIN_CONSOLE_LOCATION='/admin/login-bad' PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --health-url "http://127.0.0.1:18080/health" \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" \
        --admin-session-url "http://127.0.0.1:18080/sub_admin/admin_session.php" >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted an invalid admin console redirect target"
    fi
    assertOutputContains "$errorFile" "admin console redirect target is not /admin/login/"
    assertCurrentRelease "$releaseBase" old
}

runReleaseSmokeSkipHealthKeepsOtherProbesSelfTest() {
    local outputFile="$workRoot/releaseSmokeSkipHealth.out"
    local curlLog="$workRoot/fakeCurlSkipHealth.log"
    writeFakeCurl "$workRoot/curl"
    FAKE_CURL_LOG="$curlLog" PATH="$workRoot:$PATH" "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --keep 3 \
        --skip-health \
        --remote-cloud-summary-url "http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary" \
        --admin-login-url "http://127.0.0.1:18080/admin/login/" \
        --admin-console-url "http://127.0.0.1:18080/admin/console/" >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_SMOKE_OK"
    assertOutputNotContains "$curlLog" "GET http://127.0.0.1:18080/health"
    assertOutputContains "$curlLog" "POST http://127.0.0.1:18080/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/admin/login/"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/admin/console/"
    assertOutputContains "$curlLog" "GET http://127.0.0.1:18080/frontend/admin-console/js/app.js"
    assertCurrentRelease "$releaseBase" old
}

runSwitchRequireConfigSymlinkSelfTest() {
    local outputFile="$workRoot/switchConfigSymlink.out"
    local errorFile="$workRoot/switchConfigSymlink.err"
    local targetConfigPath="$releaseBase/releases/new/config/local.php"
    local sharedConfigPath="$releaseBase/shared/config/local.php"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --require-config-symlink \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a regular target config file when config symlink is required"
    fi
    assertOutputContains "$errorFile" "config file is not a symlink"
    rm "$targetConfigPath"
    ln -s "$sharedConfigPath" "$targetConfigPath"
    "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --require-config-symlink \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile"
    assertOutputContains "$outputFile" "DRY_RUN_OK"
    assertCurrentRelease "$releaseBase" old
}

runSwitchDryRunSelfTest() {
    local outputFile="$workRoot/switchDryRun.out"
    "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --keep 03 \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile"
    assertOutputContains "$outputFile" "DRY_RUN_OK"
    assertCurrentRelease "$releaseBase" old
}

runSwitchRejectTargetLocalStorageSelfTest() {
    local outputFile="$workRoot/switchTargetLocalStorage.out"
    local errorFile="$workRoot/switchTargetLocalStorage.err"
    local storagePath="$releaseBase/releases/new/storage/cache"
    rm "$storagePath"
    mkdir "$storagePath"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted target release-local storage"
    fi
    assertOutputContains "$errorFile" "target release storage must point to shared storage"
    assertCurrentRelease "$releaseBase" old
    rmdir "$storagePath"
    ln -s "$releaseBase/shared/storage/cache" "$storagePath"
}

runSwitchRejectNonExecutableSmokeSelfTest() {
    local outputFile="$workRoot/switchNonExecutableSmoke.out"
    local errorFile="$workRoot/switchNonExecutableSmoke.err"
    local smokeScript="$releaseBase/releases/new/deploy/scripts/release-smoke.sh"
    chmod -x "$smokeScript"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a non-executable target smoke script"
    fi
    assertOutputContains "$errorFile" "release smoke script is not executable"
    assertCurrentRelease "$releaseBase" old
    chmod +x "$smokeScript"
}

runSwitchRejectInvalidPackageSelfTest() {
    local outputFile="$workRoot/switchInvalidPackage.out"
    local errorFile="$workRoot/switchInvalidPackage.err"
    local requiredFile="$releaseBase/releases/new/public/frontend/admin-console/js/app.js"
    rm "$requiredFile"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted an invalid target release package"
    fi
    assertOutputContains "$errorFile" "required file missing"
    assertCurrentRelease "$releaseBase" old
    printf '(function (app) { app.fixture = true; })(window.app || {});\n' >"$requiredFile"
}

runSwitchApplySelfTest() {
    local outputFile="$workRoot/switchApply.out"
    "$switchReleaseScript" \
        --base "$releaseBase" \
        --release new \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile"
    assertOutputContains "$outputFile" "SWITCH_RELEASE_OK"
    assertCurrentRelease "$releaseBase" new
}

runSwitchPruneFailureKeepsTargetSelfTest() {
    local outputFile="$workRoot/switchPruneFailure.out"
    local errorFile="$workRoot/switchPruneFailure.err"
    if FAKE_BINARY_PRUNE_FAIL=1 "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release prune failure path unexpectedly succeeded"
    fi
    assertOutputContains "$outputFile" "SWITCH_RELEASE_OK"
    assertOutputContains "$errorFile" "PRUNE_RELEASES_FAILED"
    assertOutputNotContains "$errorFile" "ROLLBACK_START"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRollbackSelfTest() {
    local outputFile="$workRoot/switchRollback.out"
    local errorFile="$workRoot/switchRollback.err"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release fail \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release failure path unexpectedly succeeded"
    fi
    assertOutputContains "$errorFile" "ROLLBACK_SMOKE_OK"
    assertOutputContains "$errorFile" "ROLLBACK_OK"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRollbackToPhpReleaseSelfTest() {
    local outputFile="$workRoot/switchRollbackPhp.out"
    local errorFile="$workRoot/switchRollbackPhp.err"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/php-old"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release fail \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release PHP rollback failure path unexpectedly succeeded"
    fi
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertOutputContains "$errorFile" "ROLLBACK_START"
    assertOutputContains "$errorFile" "ROLLBACK_PHP_RELEASE_OK"
    assertOutputContains "$errorFile" "ROLLBACK_OK"
    assertOutputNotContains "$errorFile" "rollback Rust binary is not executable"
    assertCurrentRelease "$releaseBase" php-old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runPhpFallbackReadinessSelfTest() {
    local outputFile="$workRoot/phpFallbackReadiness.out"
    createPhpRelease "$releaseBase" zz-php-fallback
    "$phpFallbackReadinessCheckScript" \
        --base "$releaseBase" >"$outputFile"
    assertOutputContains "$outputFile" "PHP_FALLBACK_ROLLBACK_DRY_RUN_SKIPPED"
    assertOutputContains "$outputFile" "PHP_FALLBACK_READINESS_OK"
    assertOutputContains "$outputFile" "current_runtime=rust"
    assertOutputContains "$outputFile" "$releaseBase/releases/zz-php-fallback"
    assertCurrentRelease "$releaseBase" new
}

runCutoverReadinessRuntimeExpectationSelfTest() {
    local outputFile="$workRoot/cutoverReadinessRuntime.out"
    local failureOutput="$workRoot/cutoverReadinessRuntimeFail.out"
    local nginxConfig="$workRoot/cutover-readiness-nginx.conf"
    local unitFile="$workRoot/cutover-readiness-unit.service"

    writeFakeNginx "$workRoot/nginx"
    writeFakeSystemctl "$workRoot/systemctl"
    cat >"$nginxConfig" <<'NGINX'
server {
    listen 80;
    root /var/www/ace-network-auth/current/public;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
    }
}
NGINX
    cat >"$unitFile" <<UNIT
WorkingDirectory=$releaseBase/current
User=nginx
Group=nginx
ExecStart=$releaseBase/current/network-auth-rust serve --listen 127.0.0.1:18080 --config $releaseBase/current/config/local.php --public-root $releaseBase/current/public --schema $releaseBase/current/resources/install/schema.sql --install-lock $releaseBase/shared/storage/cache/install.lock
UNIT

    replaceCurrentLink "$releaseBase" "$releaseBase/releases/php-old"
    PATH="$workRoot:$PATH" \
        FAKE_SYSTEMD_UNIT="$unitFile" \
        FAKE_SYSTEMD_STATE=inactive \
        "$cutoverReadinessCheckScript" \
        --base "$releaseBase" \
        --nginx-config "$nginxConfig" \
        --expect-current-runtime php \
        --expect-nginx-mode php \
        --expect-service-state inactive >"$outputFile"
    assertOutputContains "$outputFile" "current_runtime=php"
    assertOutputContains "$outputFile" "CUTOVER_READINESS_OK"

    if PATH="$workRoot:$PATH" \
        FAKE_SYSTEMD_UNIT="$unitFile" \
        FAKE_SYSTEMD_STATE=inactive \
        "$cutoverReadinessCheckScript" \
        --base "$releaseBase" \
        --nginx-config "$nginxConfig" \
        --expect-runtime rust \
        --expect-nginx-mode php \
        --expect-service-state inactive >"$failureOutput" 2>&1; then
        die "cutover readiness should reject current runtime mismatch"
    fi
    assertOutputContains "$failureOutput" "current runtime mismatch: expected=rust actual=php"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
}

runPreCutoverFinalGateSelfTest() {
    local outputFile="$workRoot/preCutoverFinalGate.out"
    local nginxConfig="$workRoot/pre-cutover-final-gate-nginx.conf"
    local unitFile="$workRoot/pre-cutover-final-gate-unit.service"
    local rollbackStub="$workRoot/rollback-stub.sh"
    local preSwitchScript="$releaseBase/releases/new/deploy/scripts/pre-switch-release-smoke.sh"
    local preSwitchBackup="$workRoot/pre-switch-release-smoke.real"

    writeFakeNginx "$workRoot/nginx"
    writeFakeSystemctl "$workRoot/systemctl"
    cat >"$nginxConfig" <<'NGINX'
server {
    listen 80;
    root /var/www/ace-network-auth/current/public;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
    }
}
NGINX
    cat >"$unitFile" <<UNIT
WorkingDirectory=$releaseBase/current
User=nginx
Group=nginx
ExecStart=$releaseBase/current/network-auth-rust serve --listen 127.0.0.1:18080 --config $releaseBase/current/config/local.php --public-root $releaseBase/current/public --schema $releaseBase/current/resources/install/schema.sql --install-lock $releaseBase/shared/storage/cache/install.lock
UNIT
    cat >"$rollbackStub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'ROLLBACK_TO_PHP_DRY_RUN_OK target=stub\n'
STUB
    chmod +x "$rollbackStub"

    cp "$preSwitchScript" "$preSwitchBackup"
    cat >"$preSwitchScript" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'PRE_SWITCH_RELEASE_SMOKE_OK release=stub listen=stub\n'
STUB
    chmod +x "$preSwitchScript"

    replaceCurrentLink "$releaseBase" "$releaseBase/releases/php-old"
    PATH="$workRoot:$PATH" \
        FAKE_SYSTEMD_UNIT="$unitFile" \
        FAKE_SYSTEMD_STATE=inactive \
        "$preCutoverFinalGateScript" \
        --base "$releaseBase" \
        --release "$releaseBase/releases/new" \
        --nginx-config "$nginxConfig" \
        --rollback-script "$rollbackStub" \
        --rollback-dry-run \
        >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"
    assertOutputContains "$outputFile" "PHP_FALLBACK_ROLLBACK_DRY_RUN_OK"
    assertOutputContains "$outputFile" "PRE_SWITCH_RELEASE_SMOKE_OK"
    assertOutputContains "$outputFile" "CUTOVER_READINESS_OK"
    assertOutputContains "$outputFile" "PRE_CUTOVER_FINAL_GATE_OK"
    mv "$preSwitchBackup" "$preSwitchScript"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
}

runPostCutoverFinalGateSelfTest() {
    local outputFile="$workRoot/postCutoverFinalGate.out"
    local nginxConfig="$workRoot/post-cutover-final-gate-nginx.conf"
    local unitFile="$workRoot/post-cutover-final-gate-unit.service"
    local releaseSmokeScriptPath="$releaseBase/releases/new/deploy/scripts/release-smoke.sh"
    local releaseSmokeBackup="$workRoot/release-smoke.real"

    writeFakeNginx "$workRoot/nginx"
    writeFakeSystemctl "$workRoot/systemctl"
    cat >"$nginxConfig" <<'NGINX'
server {
    listen 80;
    location / {
        proxy_pass http://127.0.0.1:18080;
    }
}
NGINX
    cat >"$unitFile" <<UNIT
WorkingDirectory=$releaseBase/current
User=nginx
Group=nginx
ExecStart=$releaseBase/current/network-auth-rust serve --listen 127.0.0.1:18080 --config $releaseBase/current/config/local.php --public-root $releaseBase/current/public --schema $releaseBase/current/resources/install/schema.sql --install-lock $releaseBase/shared/storage/cache/install.lock
UNIT

    cp "$releaseSmokeScriptPath" "$releaseSmokeBackup"
    cat >"$releaseSmokeScriptPath" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'RELEASE_SMOKE_OK base=stub current=stub\n'
STUB
    chmod +x "$releaseSmokeScriptPath"

    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    PATH="$workRoot:$PATH" \
        FAKE_SYSTEMD_UNIT="$unitFile" \
        FAKE_SYSTEMD_STATE=active \
        "$postCutoverFinalGateScript" \
        --base "$releaseBase" \
        --release new \
        --nginx-config "$nginxConfig" \
        --public-health-url http://example.test/health \
        >"$outputFile"
    assertOutputContains "$outputFile" "RELEASE_PACKAGE_CHECK_OK"
    assertOutputContains "$outputFile" "RELEASE_SMOKE_OK"
    assertOutputContains "$outputFile" "CUTOVER_READINESS_OK"
    assertOutputContains "$outputFile" "POST_CUTOVER_FINAL_GATE_OK"
    mv "$releaseSmokeBackup" "$releaseSmokeScriptPath"
}

runSwitchRollbackSmokeFailureSelfTest() {
    local outputFile="$workRoot/switchRollbackSmokeFailure.out"
    local errorFile="$workRoot/switchRollbackSmokeFailure.err"
    local oldSmoke="$releaseBase/releases/old/deploy/scripts/release-smoke.sh"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/old"
    cat >"$oldSmoke" <<'SMOKE'
#!/usr/bin/env bash
exit 43
SMOKE
    chmod +x "$oldSmoke"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release fail \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release rollback smoke failure path unexpectedly succeeded"
    fi
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertOutputContains "$errorFile" "ROLLBACK_START"
    assertOutputNotContains "$errorFile" "ROLLBACK_OK"
    assertCurrentRelease "$releaseBase" old
    cp "$releaseSmokeScript" "$oldSmoke"
    chmod +x "$oldSmoke"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRollbackRejectNonExecutableSmokeSelfTest() {
    local outputFile="$workRoot/switchRollbackNonExecutableSmoke.out"
    local errorFile="$workRoot/switchRollbackNonExecutableSmoke.err"
    local oldSmoke="$releaseBase/releases/old/deploy/scripts/release-smoke.sh"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/old"
    chmod -x "$oldSmoke"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release fail \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release rollback accepted a non-executable smoke script"
    fi
    assertOutputContains "$errorFile" "rollback Rust smoke script is not executable"
    assertOutputNotContains "$errorFile" "ROLLBACK_OK"
    assertCurrentRelease "$releaseBase" old
    chmod +x "$oldSmoke"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchNoRollbackSelfTest() {
    local outputFile="$workRoot/switchNoRollback.out"
    local errorFile="$workRoot/switchNoRollback.err"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release fail \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release no-rollback failure path unexpectedly succeeded"
    fi
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertOutputNotContains "$errorFile" "ROLLBACK_OK"
    assertCurrentRelease "$releaseBase" fail
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectNonRustHealthSelfTest() {
    local outputFile="$workRoot/switchNonRustHealth.out"
    local errorFile="$workRoot/switchNonRustHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='{"code":0,"data":{"status":"ok"}}' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a non-Rust health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not report Rust runtime"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectMisleadingLocalHealthSelfTest() {
    local outputFile="$workRoot/switchMisleadingLocalHealth.out"
    local errorFile="$workRoot/switchMisleadingLocalHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='{"code":0,"data":{"runtime":"php","note":"rust migration ready"}}' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a misleading local health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not report Rust runtime"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectHtmlLocalHealthSelfTest() {
    local outputFile="$workRoot/switchHtmlLocalHealth.out"
    local errorFile="$workRoot/switchHtmlLocalHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_BODY='<!doctype html><pre>{"runtime":"rust"}</pre>' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted an HTML local health response"
    fi
    assertOutputContains "$errorFile" "local health URL did not return a JSON object"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectWrongLocalHealthContentTypeSelfTest() {
    local outputFile="$workRoot/switchWrongLocalHealthContentType.out"
    local errorFile="$workRoot/switchWrongLocalHealthContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_HEALTH_CONTENT_TYPE='text/html' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a non-JSON local health content type"
    fi
    assertOutputContains "$errorFile" "local health URL did not return JSON content type"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectNonRustPublicHealthSelfTest() {
    local outputFile="$workRoot/switchNonRustPublicHealth.out"
    local errorFile="$workRoot/switchNonRustPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='{"code":0,"data":{"status":"ok"}}' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a non-Rust public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not report Rust runtime"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectMisleadingPublicHealthSelfTest() {
    local outputFile="$workRoot/switchMisleadingPublicHealth.out"
    local errorFile="$workRoot/switchMisleadingPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='{"code":0,"data":{"runtime":"php","note":"rust migration ready"}}' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a misleading public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not report Rust runtime"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectHtmlPublicHealthSelfTest() {
    local outputFile="$workRoot/switchHtmlPublicHealth.out"
    local errorFile="$workRoot/switchHtmlPublicHealth.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_BODY='<!doctype html><pre>{"runtime":"rust"}</pre>' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted an HTML public health response"
    fi
    assertOutputContains "$errorFile" "public health URL did not return a JSON object"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectWrongPublicHealthContentTypeSelfTest() {
    local outputFile="$workRoot/switchWrongPublicHealthContentType.out"
    local errorFile="$workRoot/switchWrongPublicHealthContentType.err"
    writeFakeCurl "$workRoot/curl"
    if FAKE_CURL_PUBLIC_HEALTH_CONTENT_TYPE='text/html' PATH="$workRoot:$PATH" "$switchReleaseScript" \
        --base "$releaseBase" \
        --release old \
        --skip-service-restart \
        --public-health-url "http://public.example.test/health" \
        --skip-remote-api \
        --skip-web-entry \
        --no-rollback \
        --apply >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a non-JSON public health content type"
    fi
    assertOutputContains "$errorFile" "public health URL did not return JSON content type"
    assertOutputContains "$errorFile" "SWITCH_RELEASE_FAILED"
    assertCurrentRelease "$releaseBase" old
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectExternalReleaseSelfTest() {
    local outputFile="$workRoot/switchExternal.out"
    local errorFile="$workRoot/switchExternal.err"
    local externalRelease="$workRoot/external-release"
    mkdir -p "$externalRelease"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release "$externalRelease" \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted an external release path"
    fi
    assertOutputContains "$errorFile" "release path is outside releases directory"
    assertCurrentRelease "$releaseBase" new
}

runSwitchRejectNestedReleaseSelfTest() {
    local outputFile="$workRoot/switchNested.out"
    local errorFile="$workRoot/switchNested.err"
    mkdir -p "$releaseBase/releases/new/nested"
    if "$switchReleaseScript" \
        --base "$releaseBase" \
        --release "$releaseBase/releases/new/nested" \
        --skip-service-restart \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "switch-release accepted a nested release path"
    fi
    assertOutputContains "$errorFile" "release path is outside releases directory"
    assertCurrentRelease "$releaseBase" new
}

runReleaseSmokeRejectExternalCurrentSelfTest() {
    local outputFile="$workRoot/smokeExternalCurrent.out"
    local errorFile="$workRoot/smokeExternalCurrent.err"
    local externalCurrent="$workRoot/external-current"
    mkdir -p "$externalCurrent"
    replaceCurrentLink "$releaseBase" "$externalCurrent"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted current outside releases"
    fi
    assertOutputContains "$errorFile" "current release is outside releases"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runReleaseSmokeRejectNestedCurrentSelfTest() {
    local outputFile="$workRoot/smokeNestedCurrent.out"
    local errorFile="$workRoot/smokeNestedCurrent.err"
    local nestedCurrent="$releaseBase/releases/new/nested-current"
    mkdir -p "$nestedCurrent"
    replaceCurrentLink "$releaseBase" "$nestedCurrent"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted current pointing to a nested release"
    fi
    assertOutputContains "$errorFile" "current release is outside releases directory"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    assertCurrentRelease "$releaseBase" new
}

runReleaseSmokeRejectMismatchedBinarySelfTest() {
    local outputFile="$workRoot/smokeMismatchedBinary.out"
    local errorFile="$workRoot/smokeMismatchedBinary.err"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --binary "$releaseBase/releases/old/network-auth-rust" \
        --owner nginx:nginx \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a binary from a non-current release"
    fi
    assertOutputContains "$errorFile" "binary path is outside current release"
    assertCurrentRelease "$releaseBase" new
}

runReleaseSmokeRejectMismatchedConfigSelfTest() {
    local outputFile="$workRoot/smokeMismatchedConfig.out"
    local errorFile="$workRoot/smokeMismatchedConfig.err"
    replaceCurrentLink "$releaseBase" "$releaseBase/releases/new"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --config "$releaseBase/releases/old/config/local.php" \
        --owner nginx:nginx \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted a config from a non-current release"
    fi
    assertOutputContains "$errorFile" "config path is outside current release"
    assertCurrentRelease "$releaseBase" new
}

runReleaseSmokeRejectLocalStorageSelfTest() {
    local outputFile="$workRoot/smokeLocalStorage.out"
    local errorFile="$workRoot/smokeLocalStorage.err"
    local storagePath="$releaseBase/releases/new/storage/cache"
    rm "$storagePath"
    mkdir "$storagePath"
    if "$releaseSmokeScript" \
        --base "$releaseBase" \
        --owner nginx:nginx \
        --skip-health \
        --skip-remote-api \
        --skip-web-entry >"$outputFile" 2>"$errorFile"; then
        die "release-smoke accepted release-local storage"
    fi
    assertOutputContains "$errorFile" "release storage must point to shared storage"
    rmdir "$storagePath"
    ln -s "$releaseBase/shared/storage/cache" "$storagePath"
    assertCurrentRelease "$releaseBase" new
}

runSwitchNginxSslBackendSelfTest() {
    local configFile="$workRoot/prod-ssl.conf"
    local backupFile="$workRoot/prod-ssl.conf.php-backup"
    local dryRunOutput="$workRoot/switchNginxSslDryRun.out"
    local applyOutput="$workRoot/switchNginxSslApply.out"
    local restoreOutput="$workRoot/switchNginxSslRestore.out"

    writeFakeNginx "$workRoot/nginx"
    cat >"$configFile" <<'NGINX'
server {
    listen 80 default_server;
    server_name example.test;
    root /var/www/ace-network-auth/current/public;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        allow all;
        try_files $uri =404;
    }

    location / {
        return 301 https://example.test$request_uri;
    }
}

server {
    listen 443 ssl default_server;
    server_name example.test;
    http2 on;
    root /var/www/ace-network-auth/current/public;
    index index.php index.html;
    access_log /var/log/nginx/ace-network-auth.access.log main;
    error_log /var/log/nginx/ace-network-auth.error.log warn;
    client_max_body_size 20m;
    ssl_certificate /etc/letsencrypt/live/example.test/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.test/privkey.pem;
    ssl_session_cache shared:ACEAuthSSL:10m;
    ssl_session_timeout 1d;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=15552000" always;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        allow all;
        try_files $uri =404;
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        fastcgi_param HTTPS on;
        fastcgi_pass unix:/run/php-fpm/www.sock;
    }
}
NGINX
    cp "$configFile" "$backupFile"

    PATH="$workRoot:$PATH" "$switchNginxSslBackendScript" \
        --mode rust \
        --config "$configFile" \
        --listen 127.0.0.1:18080 >"$dryRunOutput"
    assertOutputContains "$dryRunOutput" "NGINX_SSL_BACKEND_DRY_RUN_OK"
    assertOutputContains "$dryRunOutput" "proxy_pass http://127.0.0.1:18080;"
    assertOutputContains "$dryRunOutput" "fastcgi_pass unix:/run/php-fpm/www.sock;"

    PATH="$workRoot:$PATH" "$switchNginxSslBackendScript" \
        --mode rust \
        --config "$configFile" \
        --backup "$backupFile" \
        --listen 127.0.0.1:18080 \
        --skip-reload \
        --apply >"$applyOutput"
    assertOutputContains "$applyOutput" "NGINX_SSL_BACKEND_SWITCH_OK"
    grep -Fq 'return 301 https://example.test$request_uri;' "$configFile" || die "HTTP redirect server was not preserved"
    grep -Fq 'ssl_certificate /etc/letsencrypt/live/example.test/fullchain.pem;' "$configFile" || die "SSL certificate directive was not preserved"
    grep -Fq 'location ^~ /.well-known/acme-challenge/' "$configFile" || die "ACME location was not preserved"
    grep -Fq 'proxy_pass http://127.0.0.1:18080;' "$configFile" || die "Rust proxy was not rendered"
    grep -Fq 'location = /api/v1/index.php {' "$configFile" || die "legacy API location was not rendered"
    grep -Fq 'proxy_pass http://127.0.0.1:18080$request_uri;' "$configFile" || die "legacy API location does not preserve request_uri"
    if grep -Fq 'fastcgi_pass unix:/run/php-fpm/www.sock;' "$configFile"; then
        die "PHP fastcgi backend remained in Rust SSL config"
    fi

    PATH="$workRoot:$PATH" "$switchNginxSslBackendScript" \
        --mode php \
        --config "$configFile" \
        --backup "$backupFile" \
        --skip-reload \
        --apply >"$restoreOutput"
    assertOutputContains "$restoreOutput" "NGINX_SSL_BACKEND_SWITCH_OK"
    cmp -s "$backupFile" "$configFile" || die "PHP SSL config restore did not match backup"
}

main() {
    [[ -f "$releaseSmokeScript" ]] || die "release-smoke.sh not found"
    [[ -f "$cutoverReadinessCheckScript" ]] || die "cutover-readiness-check.sh not found"
    [[ -f "$installRuntimeServiceScript" ]] || die "install-runtime-service.sh not found"
    [[ -f "$phpFallbackReadinessCheckScript" ]] || die "php-fallback-readiness-check.sh not found"
    [[ -f "$postCutoverFinalGateScript" ]] || die "post-cutover-final-gate.sh not found"
    [[ -f "$preCutoverFinalGateScript" ]] || die "pre-cutover-final-gate.sh not found"
    [[ -f "$preSwitchReleaseSmokeScript" ]] || die "pre-switch-release-smoke.sh not found"
    [[ -f "$rollbackToPhpReleaseScript" ]] || die "rollback-to-php-release.sh not found"
    [[ -f "$switchNginxBackendScript" ]] || die "switch-nginx-backend.sh not found"
    [[ -f "$switchNginxSslBackendScript" ]] || die "switch-nginx-ssl-backend.sh not found"
    [[ -f "$switchReleaseScript" ]] || die "switch-release.sh not found"
    [[ -f "$releasePackageCheckScript" ]] || die "release-package-check.sh not found"
    [[ -f "$assembleReleasePackageScript" ]] || die "assemble-release-package.sh not found"
    prepareFixture
    runReleasePackageCheckSelfTest
    runReleasePackageRejectLocalStorageSelfTest
    runReleasePackageRejectWritableDirectorySelfTest
    runReleasePackageRejectEmptyFileSelfTest
    runReleasePackageRejectWrongStaticMarkerSelfTest
    runReleasePackageRejectSymlinkedRequiredFileSelfTest
    runReleasePackageRejectSymlinkedExecutableSelfTest
    runAssembleReleasePackageSelfTest
    runReleasePackageRequireConfigSymlinkSelfTest
    runReleaseSmokeSelfTest
    runReleaseSmokeRequireConfigSymlinkSelfTest
    runReleaseSmokeRemoteApiSelfTest
    runReleaseSmokeRejectNonRustHealthSelfTest
    runReleaseSmokeRejectMisleadingLocalHealthSelfTest
    runReleaseSmokeRejectHtmlLocalHealthSelfTest
    runReleaseSmokeRejectWrongLocalHealthContentTypeSelfTest
    runReleaseSmokeRejectNonRustPublicHealthSelfTest
    runReleaseSmokeRejectMisleadingPublicHealthSelfTest
    runReleaseSmokeRejectHtmlPublicHealthSelfTest
    runReleaseSmokeRejectWrongPublicHealthContentTypeSelfTest
    runReleaseSmokeRejectNonJsonRemoteApiSelfTest
    runReleaseSmokeRejectNonJsonAdminSessionSelfTest
    runReleaseSmokeRejectWrongJsonContentTypeSelfTest
    runReleaseSmokeRejectWrongJsonStatusSelfTest
    runReleaseSmokeRejectWrongAdminLoginStatusSelfTest
    runReleaseSmokeRejectWrongAdminLoginContentTypeSelfTest
    runReleaseSmokeRejectEmptyStaticAssetSelfTest
    runReleaseSmokeRejectWrongStaticAssetSelfTest
    runReleaseSmokeRejectWrongConsoleRedirectSelfTest
    runReleaseSmokeSkipHealthKeepsOtherProbesSelfTest
    runSwitchRequireConfigSymlinkSelfTest
    runSwitchDryRunSelfTest
    runSwitchRejectTargetLocalStorageSelfTest
    runSwitchRejectNonExecutableSmokeSelfTest
    runSwitchRejectInvalidPackageSelfTest
    runSwitchApplySelfTest
    runSwitchPruneFailureKeepsTargetSelfTest
    runSwitchRollbackSelfTest
    runSwitchRollbackToPhpReleaseSelfTest
    runPhpFallbackReadinessSelfTest
    runCutoverReadinessRuntimeExpectationSelfTest
    runPreCutoverFinalGateSelfTest
    runPostCutoverFinalGateSelfTest
    runSwitchRollbackSmokeFailureSelfTest
    runSwitchRollbackRejectNonExecutableSmokeSelfTest
    runSwitchNoRollbackSelfTest
    runSwitchRejectNonRustHealthSelfTest
    runSwitchRejectMisleadingLocalHealthSelfTest
    runSwitchRejectHtmlLocalHealthSelfTest
    runSwitchRejectWrongLocalHealthContentTypeSelfTest
    runSwitchRejectNonRustPublicHealthSelfTest
    runSwitchRejectMisleadingPublicHealthSelfTest
    runSwitchRejectHtmlPublicHealthSelfTest
    runSwitchRejectWrongPublicHealthContentTypeSelfTest
    runSwitchRejectExternalReleaseSelfTest
    runSwitchRejectNestedReleaseSelfTest
    runReleaseSmokeRejectExternalCurrentSelfTest
    runReleaseSmokeRejectNestedCurrentSelfTest
    runReleaseSmokeRejectMismatchedBinarySelfTest
    runReleaseSmokeRejectMismatchedConfigSelfTest
    runReleaseSmokeRejectLocalStorageSelfTest
    runSwitchNginxSslBackendSelfTest
    printf 'RELEASE_SCRIPT_SELF_TEST_OK\n'
}

main "$@"
