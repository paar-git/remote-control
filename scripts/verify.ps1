<#
.SYNOPSIS
    Runs every check that must pass before a phase is considered complete.

.DESCRIPTION
    Formatting, linting, type checking and tests for both the Rust and TypeScript
    halves of the workspace. Exits non-zero if any step fails, so it can be used as a
    pre-commit hook or a CI entry point.
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

$failures = @()

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)

    Write-Host "==> $Name" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    & $Body
    if ($LASTEXITCODE -ne 0) {
        $script:failures += $Name
        Write-Host "    FAILED: $Name" -ForegroundColor Red
    }
}

if ($Fix) {
    Invoke-Step 'rust format (write)' { cargo fmt --all }
    Invoke-Step 'js format (write)'   { pnpm format }
    Invoke-Step 'js lint (fix)'       { pnpm lint:fix }
} else {
    Invoke-Step 'rust format'  { cargo fmt --all -- --check }
    Invoke-Step 'js format'    { pnpm format:check }
    Invoke-Step 'js lint'      { pnpm lint }
}

Invoke-Step 'rust clippy'   { cargo clippy --workspace --all-targets --all-features -- -D warnings }
Invoke-Step 'rust tests'    { cargo test --workspace }
Invoke-Step 'js typecheck'  { pnpm -r typecheck }
Invoke-Step 'js tests'      { pnpm -r test:run }
Invoke-Step 'frontend build' { pnpm --filter '@rc/desktop-client' build }

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) step(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host 'All checks passed.' -ForegroundColor Green
