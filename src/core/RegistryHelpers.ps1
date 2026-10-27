# src\core\RegistryHelpers.ps1
# Shared utilities for registry operations and CI detection.

# Note: the exit codes used to be declared here as 'enum ExitCode', with
# UnsupportedEnvironment = 1. That numbering contradicted the script's own
# documentation, which described 1 as "user cancellation / bad interactive
# input" and used 3 for validation failure. The canonical contract now lives
# in src/core/ExitCode.ps1 as 'AuditExitCode'.

function Test-CI {
    return ($env:CI -eq 'true')
}

function Backup-RegistryState {
    <#
        .SYNOPSIS
            Exports a registry key to a .reg file and verifies the result.

        .DESCRIPTION
            Runs reg.exe export and then confirms that the command actually
            succeeded and that a usable backup file was written.

            The previous implementation launched reg.exe via Start-Process and
            treated "the process started without throwing" as success. reg.exe
            reports a missing or inaccessible key by writing to stderr and
            exiting non-zero - it does not raise a .NET exception - so the old
            code printed "Backup created" while writing no file at all. For a
            tool that mutates the registry, that false success is worse than
            no backup.

            This version checks three things:
              1. reg.exe exit code is 0
              2. the backup file exists and is non-empty
              3. the file actually parses as a registry script

        .PARAMETER ext
            The file extension whose registry branch is exported, e.g. '.txt'.

        .PARAMETER BackupPath
            Destination path for the .reg file.

        .OUTPUTS
            Boolean. $true only when a verified backup exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$ext,

        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$BackupPath
    )

    $keyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext"

    # reg.exe writes the file itself, so the destination directory has to
    # exist before the call. Resolve it first so a bad path is reported as
    # a clean failure rather than an obscure reg.exe error.
    $resolvedBackup = $null
    try {
        $resolvedBackup = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupPath)
    }
    catch {
        Write-Host "[X] Backup failed: invalid backup path '$BackupPath'" -ForegroundColor Red
        return $false
    }

    $backupDirectory = Split-Path -Path $resolvedBackup -Parent
    if ($backupDirectory -and -not (Test-Path -LiteralPath $backupDirectory)) {
        Write-Host "[X] Backup failed: directory '$backupDirectory' does not exist" -ForegroundColor Red
        return $false
    }

    # Remove any stale file so a leftover from a previous run cannot be
    # mistaken for a fresh backup.
    #
    # A directory at the backup path is not a stale file - it is a broken
    # destination that reg.exe cannot write to. Remove-Item on a directory
    # without -Recurse raises a raw .NET NullReferenceException on some
    # PowerShell builds, which would escape this function and surface to the
    # caller as a crash instead of a clean "backup failed" result. Detect the
    # directory up front and fail with a readable reason.
    $existingItem = Get-Item -LiteralPath $resolvedBackup -Force -ErrorAction SilentlyContinue
    if ($existingItem -and $existingItem.PSIsContainer) {
        Write-Host "[X] Backup failed: backup path '$resolvedBackup' is a directory, not a file" -ForegroundColor Red
        return $false
    }

    if ($existingItem) {
        Remove-Item -LiteralPath $resolvedBackup -Force -ErrorAction SilentlyContinue
    }

    $output = & reg.exe export $keyPath $resolvedBackup /y 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $reason = ($output | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = "reg.exe exited with code $exitCode"
        }
        Write-Host "[X] Backup failed: $reason" -ForegroundColor Red
        return $false
    }

    if (-not (Test-Path -LiteralPath $resolvedBackup)) {
        Write-Host "[X] Backup failed: reg.exe reported success but no file was written" -ForegroundColor Red
        return $false
    }

    $backupFile = Get-Item -LiteralPath $resolvedBackup -ErrorAction SilentlyContinue
    if (-not $backupFile -or $backupFile.Length -eq 0) {
        Write-Host "[X] Backup failed: backup file is empty" -ForegroundColor Red
        return $false
    }

    # Verify the file is a well-formed registry script rather than a
    # truncated or corrupt export.
    try {
        $header = Get-Content -LiteralPath $resolvedBackup -TotalCount 1 -ErrorAction Stop
    }
    catch {
        Write-Host "[X] Backup failed: backup file could not be read - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    if ($header -notmatch '^Windows Registry Editor Version 5\.00') {
        Write-Host "[X] Backup failed: backup file is not a registry script" -ForegroundColor Red
        return $false
    }

    Write-Host "[Y] Backup created: $resolvedBackup" -ForegroundColor Green
    return $true
}
