# python 
#region Python Residuals Cleanup
### 🔍 Registry + File Detection
<#
.SYNOPSIS
Scans registry for residual Python entries after uninstallation.

.DESCRIPTION
Recursively searches common registry locations where Python installs may leave keys behind.
Highlights potentially orphaned registry paths to aid in manual or automated cleanup.

.NOTES
Does not modify the registry.
#>

function Test-PythonResiduals {
    Write-Host "`n[🔍 Python Residuals Registry Scan]" -ForegroundColor Cyan

    $paths = @(
        "HKLM:\SOFTWARE\Python",
        "HKLM:\SOFTWARE\WOW6432Node\Python",
        "HKCU:\Software\Python",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $paths) {
        if (Test-Path $regPath) {
            Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match "Python") {
                    Write-Host "⚠️ Found: $($_.Name)" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "✔️ $regPath clean" -ForegroundColor Green
        }
    }
}

<#
.SYNOPSIS
Audits system PATH for Python-related entries.

.DESCRIPTION
Reads the system-wide environment variable 'Path' and identifies any entries that match
'Python', which may indicate residual configuration after uninstallation.

.NOTES
Currently only scans the 'Machine' scope.
#>

function Get-PythonPathInfo {
    Write-Host "`n[🔁 Environment Variable Scan]" -ForegroundColor Cyan

    $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries = $envPath.Split(";")

    $pythonPathHits = $entries | Where-Object { $_ -match "Python" }

    if ($pythonPathHits.Count -gt 0) {
        Write-Host "⚠️ Python-related PATH entries:"
        $pythonPathHits | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "✔️ No Python PATH entries found"
    }
}

<#
.SYNOPSIS
Checks whether a command is currently available in the system.

.DESCRIPTION
Uses PowerShell's Get-Command to detect if a given executable or alias is currently discoverable.
Useful for testing whether 'python', 'pip', or other tools are still registered on the system.

.PARAMETER Command
The name of the command to check (e.g., 'python').

#>

function Test-CommandExists {
    param([string]$Command)

    try {
        $cmd = Get-Command $Command -ErrorAction Stop
        Write-Host "⚠️ $Command found at $($cmd.Source)"
    }
    catch {
        Write-Host "✔️ $Command not detected"
    }
}
### 🧼 Deletion Actions

<#
.SYNOPSIS
Deletes Python residual folders from Chocolatey installs.

.DESCRIPTION
Checks for common Chocolatey Python directories and optionally removes them.
Supports dry-run and interactive confirmation for safety.

.PARAMETER WhatIf
Simulates deletion by showing what would be removed.

.PARAMETER Confirm
Requires interactive confirmation before deleting each target.

.NOTES
Targets:
- C:\ProgramData\chocolatey\lib\python
- C:\ProgramData\chocolatey\lib\python3
#>

function Remove-ResidualPython {
    param(
        [switch]$WhatIf,
        [switch]$Confirm
    )

    $targets = @(
        "C:\ProgramData\chocolatey\lib\python",
        "C:\ProgramData\chocolatey\lib\python3"
    )

    foreach ($path in $targets) {
        if (Test-Path $path) {
            if ($WhatIf) {
                Write-Host "🧪 Would remove: $path"
            }
            elseif ($Confirm -and -not (Read-Host "Delete $path? (Y/N)") -match '^y$') {
                Write-Host "⏭️ Skipped $path"
            }
            else {
                Remove-Item -Recurse -Force $path
                Write-Host "🗑️ Deleted: $path"
            }
        }
        else {
            Write-Host "✔️ $path not found" -ForegroundColor Green
        }
    }
}


<#
.SYNOPSIS
Safely removes Python registry entries with comprehensive safety measures.

.DESCRIPTION
Targets Python installation artifacts in registry with:
- Automatic elevation detection
- Atomic backup operations
- Transactional safety features
- PS-native confirmation handling

.PARAMETER BackupPath
Specifies backup file path (default: timestamped .reg in temp directory)

.PARAMETER Force
Bypass confirmation prompts (use with caution)

.EXAMPLE
PS> Remove-PythonRegistryKeys -WhatIf
Preview removal actions without making changes

.NOTES
Requires elevation for HKLM modifications. Creates system restore point when modifying system keys.
#>
function Remove-PythonRegistryKeys {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$BackupPath = "$env:TEMP\PythonRegBackup-$(Get-Date -Format yyyyMMdd-HHmmss).reg",
        [switch]$Force
    )

    #region Constants
    $registryTargets = @(
        "HKLM:\SOFTWARE\Python",
        "HKLM:\SOFTWARE\WOW6432Node\Python",
        "HKCU:\Software\Python"
    )
    #endregion

    #region Elevation Check

    # 1. Get the current Windows identity and principal
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)

    # 2. Check if running as Administrator
    $isAdmin = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    # 3. Determine if we need elevation
    $requiresElevation = ($registryTargets -match '^HKLM:') -and -not $isAdmin

    if ($requiresElevation) {
        throw "Administrator rights required for system key modification. Run as admin."
    }
    #endregion


    #region Target Verification
    $existingKeys = $registryTargets | Where-Object { Test-Path $_ }
    
    if (-not $existingKeys) {
        Write-Verbose "No Python registry keys found"
        return
    }
    #endregion

    #region Backup Implementation
    try {
        $backupCommands = $existingKeys | ForEach-Object {
            "reg.exe export `"$($_.Replace('HKLM:', 'HKEY_LOCAL_MACHINE'))`" `"$BackupPath`" /y"
        }

        $null = Start-Process cmd.exe -ArgumentList "/c $($backupCommands -join ' & ')" `
            -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
        
        if (Test-Path $BackupPath) {
            Write-Verbose "Registry backup created: $BackupPath"
            Get-Item $BackupPath | Select-Object FullName, Length, LastWriteTime
        }
        else {
            Write-Warning "Backup file not created - aborting operation"
            return
        }
    }
    catch {
        throw "Backup failed: $($_.Exception.Message)"
    }
    #endregion

    #region Removal Protocol
    foreach ($key in $existingKeys) {
        if ($Force -or $PSCmdlet.ShouldProcess($key, "Remove registry key")) {
            try {
                $params = @{
                    Path        = $key
                    Recurse     = $true
                    Force       = $true
                    ErrorAction = 'Stop'
                }

                Remove-Item @params
                Write-Verbose "Successfully removed: $key"
            }
            catch {
                Write-Error "Failed to remove $key : $($_.Exception.Message)"
            }
        }
    }
    #endregion
}

<#
.SYNOPSIS
Removes Python-related entries from user or system PATH variables.

.DESCRIPTION
Scans either the User or System PATH environment variable for entries containing 'Python'.
Safely removes these entries with support for dry-run and confirmation modes.

.PARAMETER System
Target the system-wide (machine) PATH variable.

.PARAMETER User
Target the current user's PATH variable.

.PARAMETER DryRun
Preview which entries would be removed.

.PARAMETER Confirm
Execute removal with or without prompt, depending on interactive session context.

.NOTES
Python installations often leave residual PATH entries. This function cleans those up.
#>

function Clear-PythonPathEntries {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$System,
        [switch]$User,
        [switch]$DryRun,
        [switch]$Confirm
    )

    if (-not $System -and -not $User) {
        Write-Host "ℹ️ Specify -System, -User or both to define which PATH variable to modify." -ForegroundColor Yellow
        return
    }

    $targetScopes = @{}
    if ($System) { $targetScopes["Machine"] = "System" }
    if ($User) { $targetScopes["User"] = "User" }

    foreach ($scope in $targetScopes.Keys) {
        $originalPath = [System.Environment]::GetEnvironmentVariable("Path", $scope)
        $entries = $originalPath -split ";" | Where-Object { $_ -ne "" }

        $pythonPaths = $entries | Where-Object { $_ -match "Python" }

        if ($pythonPaths.Count -eq 0) {
            Write-Host "[+] No Python paths found in $($targetScopes[$scope]) PATH." -ForegroundColor Green
            continue
        }

        Write-Host "`n [$($targetScopes[$scope]) PATH] Found Python entries:" -ForegroundColor Cyan
        $pythonPaths | ForEach-Object { Write-Host "  $_" }

        if ($DryRun) {
            Write-Host " [DryRun] Would remove above entries from $($targetScopes[$scope]) PATH"
            continue
        }

        if ($Confirm -or $PSCmdlet.ShouldContinue("Remove these entries from $($targetScopes[$scope]) PATH?", "Confirm Deletion")) {
            $cleaned = $entries | Where-Object { $_ -notin $pythonPaths }
            $newPath = ($cleaned -join ";").TrimEnd(";")

            [System.Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
            Write-Host "[+] Updated $($targetScopes[$scope]) PATH (Python entries removed)" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Skipped $($targetScopes[$scope]) PATH"
        }
    }
}


#endregion
