param(
    [string]$ZigExe = $env:ZIG_EXE,
    [string]$CargoHome = $env:CARGO_HOME,
    [string]$RustupHome = $env:RUSTUP_HOME,
    [string]$WrapperDirectory = '',
    [string]$ZigCacheDirectory = '',
    [switch]$SkipTargetInstall
)

$ErrorActionPreference = 'Stop'

function Fail([string]$message) {
    Write-Error $message
    exit 1
}

function NormalizeOptionalPath([string]$label, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return ''
    }
    return ([System.IO.Path]::GetFullPath($path))
}

function NormalizeRequiredPath([string]$label, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        Fail "$label is required"
    }
    return ([System.IO.Path]::GetFullPath($path))
}

function ResolveZigExe([string]$candidate) {
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
        return $candidate
    }

    $command = Get-Command zig -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Fail "Zig executable not found. Install Zig and add it to PATH, or pass -ZigExe <path>."
    }

    return $command.Source
}

function WriteCommandWrapper([string]$wrapperPath, [string]$commandLine) {
    $wrapperContent = @(
        '@echo off',
        $commandLine
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $wrapperPath) | Out-Null
    Set-Content -LiteralPath $wrapperPath -Value $wrapperContent -Encoding ASCII
}

function ResolveRustLld() {
    $sysroot = rustc --print sysroot
    $rustLld = Get-ChildItem -LiteralPath $sysroot -Recurse -Filter 'rust-lld.exe' |
        Select-Object -First 1

    if ($null -eq $rustLld) {
        Fail "rust-lld.exe not found under Rust sysroot: $sysroot"
    }

    return $rustLld.FullName
}

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$defaultWrapperRoot = Join-Path $projectRoot 'target\zig-wrapper'
$defaultZigCacheRoot = Join-Path $projectRoot 'target\zig-cache'
$zigPath = NormalizeRequiredPath 'ZigExe' (ResolveZigExe $ZigExe)
$cargoHomePath = NormalizeOptionalPath 'CargoHome' $CargoHome
$rustupHomePath = NormalizeOptionalPath 'RustupHome' $RustupHome
$wrapperRoot = NormalizeRequiredPath 'WrapperDirectory' $(if ([string]::IsNullOrWhiteSpace($WrapperDirectory)) { $defaultWrapperRoot } else { $WrapperDirectory })
$zigCacheRoot = NormalizeRequiredPath 'ZigCacheDirectory' $(if ([string]::IsNullOrWhiteSpace($ZigCacheDirectory)) { $defaultZigCacheRoot } else { $ZigCacheDirectory })
$compilerWrapperPath = Join-Path $wrapperRoot 'zig-musl-cc.cmd'
$archiveWrapperPath = Join-Path $wrapperRoot 'zig-ar.cmd'

if (-not (Test-Path -LiteralPath $zigPath -PathType Leaf)) {
    Fail "Zig executable not found: $zigPath"
}

if ($cargoHomePath -ne '') {
    $env:CARGO_HOME = $cargoHomePath
    $env:Path = "$cargoHomePath\bin;$env:Path"
}
if ($rustupHomePath -ne '') {
    $env:RUSTUP_HOME = $rustupHomePath
}
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $zigCacheRoot 'global'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $zigCacheRoot 'local'

WriteCommandWrapper $compilerWrapperPath ('{0} cc -target x86_64-linux-musl %*' -f $zigPath)
WriteCommandWrapper $archiveWrapperPath ('{0} ar %*' -f $zigPath)
$rustLldPath = NormalizeRequiredPath 'RustLld' (ResolveRustLld)

$env:CC_x86_64_unknown_linux_musl = $compilerWrapperPath
$env:AR_x86_64_unknown_linux_musl = $archiveWrapperPath
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = $rustLldPath
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = '-Clinker-flavor=ld.lld'
$env:CFLAGS_x86_64_unknown_linux_musl = '-fPIC -fno-sanitize=undefined'
$env:CRATE_CC_NO_DEFAULTS = '1'

New-Item -ItemType Directory -Force -Path $env:ZIG_GLOBAL_CACHE_DIR, $env:ZIG_LOCAL_CACHE_DIR | Out-Null

if (-not $SkipTargetInstall) {
    rustup target add x86_64-unknown-linux-musl
}

Push-Location $projectRoot
try {
    cargo build --release --target x86_64-unknown-linux-musl -j1
    $binaryPath = Join-Path $projectRoot 'target\x86_64-unknown-linux-musl\release\network-auth-rust'
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        Fail "Linux binary was not produced: $binaryPath"
    }
    Write-Output "LINUX_BINARY_OK $binaryPath"
}
finally {
    Pop-Location
}
