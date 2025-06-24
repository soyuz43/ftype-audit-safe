# src\core\RegistryHelpers.ps1
# Shared utilities for registry operations, CI detection, and standard exit codes

function Test-CI {
    return ($env:CI -eq 'true')
}

enum ExitCode {
    Success = 0
    UnsupportedEnvironment = 1
    RegistryAccessFailure = 2
    InsufficientElevation = 3
}

function Backup-RegistryState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$ext,

        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$BackupPath
    )

    $keyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext"
    $quotedBackupPath = '"' + $BackupPath + '"'

    try {
        Start-Process reg -ArgumentList "export", $keyPath, $quotedBackupPath, "/y" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "[Y] Backup created: $BackupPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[X] Backup failed: $_" -ForegroundColor Red
        return $false
    }
}
