<#
.SYNOPSIS
    Runs every check that must pass before a change is considered complete.

.DESCRIPTION
    Invokes `pnpm verify` so the scripted path and the npm script stay the same
    set of steps. Pass -Fix to rewrite formatted and linted files first.
#>
[CmdletBinding()]
param(
    # Rewrite files instead of only checking them.
    [switch]$Fix
)

# Deliberately NOT 'Stop'. In Windows PowerShell, a native tool writing to stderr
# raises a NativeCommandError under 'Stop', which would abort the run on cargo's and
# pnpm's ordinary progress output. Each step's real exit code is checked instead.
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Fix) {
    Write-Host '==> rust format (write)' -ForegroundColor Cyan
    cargo fmt --all
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host '==> js format (write)' -ForegroundColor Cyan
    pnpm format
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host '==> js lint (fix)' -ForegroundColor Cyan
    pnpm lint:fix
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host '==> pnpm verify' -ForegroundColor Cyan
pnpm verify
exit $LASTEXITCODE
