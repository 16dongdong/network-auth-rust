param(
    [switch]$CurrentHistory
)

$ErrorActionPreference = 'Stop'

function Invoke-GitLines {
    param([string[]]$Arguments)

    $output = & git @Arguments
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }

    return @($output)
}

function Assert-NoTrackedPrivatePath {
    $trackedFiles = Invoke-GitLines @('ls-files')
    $privatePathPattern = '(^|/)(config/local\.php|\.env(\..*)?|.*\.private\.md|.*\.(pem|key|p12|pfx|crt|csr))$'
    $matches = $trackedFiles | Where-Object { $_ -match $privatePathPattern }

    if ($matches.Count -gt 0) {
        Write-Error "Tracked private paths found:`n$($matches -join "`n")"
    }
}

function Assert-NoSecretText {
    $secretPattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|ICP备'
    $matches = Invoke-GitLines @(
        'grep',
        '-n',
        '-I',
        '-E',
        '-e',
        $secretPattern,
        '--',
        '.',
        ':!scripts/openSourceAudit.ps1'
    )

    if ($matches.Count -gt 0) {
        Write-Error "Potential secrets or private identifiers found:`n$($matches -join "`n")"
    }
}

function Assert-CurrentHistoryClean {
    $historyPattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|ICP备'
    $matches = Invoke-GitLines @(
        'grep',
        '-n',
        '-I',
        '-E',
        '-e',
        $historyPattern,
        'HEAD',
        '--',
        '.',
        ':!scripts/openSourceAudit.ps1'
    )

    if ($matches.Count -gt 0) {
        Write-Error "Current branch history contains private identifiers:`n$($matches -join "`n")"
    }
}

Assert-NoTrackedPrivatePath
Assert-NoSecretText

if ($CurrentHistory) {
    Assert-CurrentHistoryClean
}

Write-Output 'OPEN_SOURCE_AUDIT_OK'
