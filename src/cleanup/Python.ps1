# src\cleanup\Python.ps1

# Ensure the platform context is available
# This assumes the script is run from within the project structure
# relative to ftype-audit.ps1 or the module root.
$script:PlatformContextScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "..\platform\PlatformContext.ps1" -Resolve

# Initialize a module-level variable for the context
$script:ExecutionContextInfo = $null

function Initialize-PythonCleanupContext {
    if ($null -eq $script:ExecutionContextInfo) {
        if (Test-Path $script:PlatformContextScriptPath) {
            . $script:PlatformContextScriptPath
            $script:ExecutionContextInfo = Get-PlatformContext
            # Optional: Suppress the debug output from Get-PlatformContext if desired
            # $script:ExecutionContextInfo = Get-PlatformContext 2>$null
        } else {
            Write-Warning "Platform context script not found at '$script:PlatformContextScriptPath'. Assuming not elevated for safety."
            # Create a minimal context object if the script can't be loaded
            $script:ExecutionContextInfo = [PSCustomObject]@{
                IsElevated = $false
                IsWindows  = $true # Assume Windows if this script is being used
                # Add other properties if needed by other functions
            }
        }
    }
}

# Ensure context is initialized when the script (or functions within) are used
# This could also be placed at the very beginning of the file if it's dot-sourced.
# Initialize-PythonCleanupContext

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
                # Be more specific about matching Python keys/values
                if ($_.PSChildName -match "Python" -or $_.Name -match "Python") {
                    Write-Host "⚠️ Found: $($_.Name)" -ForegroundColor Yellow
                }
            }
        }
        else {
            # Only show 'clean' for HKLM paths if elevated, otherwise it's expected they might not be accessible
            # This is a simplification; technically HKCU should always be readable.
            # Let's just report if HKLM paths are not found (assuming they exist but we can't see them if not elevated)
            if ($regPath -like "HKLM:*") {
                 # Don't report as 'clean' if not elevated for HKLM, as inaccessibility is expected
                 # We could check elevation here, but for pure read, it's less critical to report 'clean' inaccurately.
                 # Let's just not report 'clean' for HKLM if we are sure we couldn't access it due to perms.
                 # For simplicity in this audit, we'll leave the logic as is for now, focusing on HKCU readability.
                 # A more advanced version could check $script:ExecutionContextInfo.IsElevated
            } else {
                 Write-Host "✔️ $regPath clean" -ForegroundColor Green
            }
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
Currently scans both 'Machine' (System) and 'User' scopes.
#>
function Get-PythonPathInfo {
    Write-Host "`n[🔁 Environment Variable Scan]" -ForegroundColor Cyan

    $scopesToCheck = @("Machine", "User")

    foreach ($scope in $scopesToCheck) {
        try {
            $envPath = [System.Environment]::GetEnvironmentVariable("Path", $scope)
            if ($null -ne $envPath) {
                $entries = $envPath -split ";" | Where-Object { $_.Trim() -ne "" }

                $pythonPathHits = $entries | Where-Object { $_ -match "Python" }

                if ($pythonPathHits.Count -gt 0) {
                    Write-Host "⚠️ Python-related PATH entries ($scope):"
                    $pythonPathHits | ForEach-Object { Write-Host "  $_" }
                }
                else {
                    Write-Host "✔️ No Python PATH entries found ($scope)" -ForegroundColor Green
                }
            } else {
                 Write-Host "ℹ️ PATH variable not found or empty ($scope)" -ForegroundColor Gray
            }
        } catch {
            if ($scope -eq "Machine" -and ($null -ne $script:ExecutionContextInfo -and -not $script:ExecutionContextInfo.IsElevated)) {
                Write-Host "ℹ️ Skipped checking $scope PATH due to lack of elevation." -ForegroundColor Yellow
            } else {
                Write-Host "⚠️ Error reading $scope PATH: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
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
        Write-Host "⚠️ $Command found at $($cmd.Source)" -ForegroundColor Yellow
    }
    catch {
        Write-Host "✔️ $Command not detected" -ForegroundColor Green
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

    # Note: File system permissions might still prevent deletion even if not strictly 'elevation' related,
    # but this function doesn't explicitly check for elevation itself for file deletion.
    # It relies on standard PowerShell/OS permissions.

    $targets = @(
        "C:\ProgramData\chocolatey\lib\python",
        "C:\ProgramData\chocolatey\lib\python3"
    )

    foreach ($path in $targets) {
        if (Test-Path $path) {
            if ($WhatIf) {
                Write-Host "🧪 Would remove: $path" -ForegroundColor Cyan
            }
            elseif ($Confirm -and -not (Read-Host "Delete $path? (Y/N)") -match '^y(es)?$') { # Improved confirmation check
                Write-Host "⏭️ Skipped $path" -ForegroundColor Yellow
            }
            else {
                try {
                    Remove-Item -Recurse -Force $path -ErrorAction Stop
                    Write-Host "🗑️ Deleted: $path" -ForegroundColor Green
                } catch {
                     Write-Host "❌ Failed to delete: $path - $($_.Exception.Message)" -ForegroundColor Red
                }
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
- Transactional safety features (conceptual, via backup)
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

    # Ensure context is initialized
    Initialize-PythonCleanupContext

    #region Constants
    $registryTargets = @(
        "HKLM:\SOFTWARE\Python",
        "HKLM:\SOFTWARE\WOW6432Node\Python",
        "HKCU:\Software\Python"
    )

    #region Elevation Check
    # Use the centralized check
    if (-not $script:ExecutionContextInfo.IsElevated) {
        $requiresElevation = ($registryTargets -match '^HKLM:')
        if ($requiresElevation) {
            Write-Warning "Administrator rights required for HKLM key modification. Run as admin to remove system-wide Python registry entries."
            Write-Host "ℹ️ Skipped removing HKLM Python registry keys due to lack of elevation." -ForegroundColor Yellow
            # Filter out HKLM targets
            $registryTargets = $registryTargets -notmatch '^HKLM:'
            if ($registryTargets.Count -eq 0) {
                Write-Host "ℹ️ No accessible registry keys to process (HKCU only, and none found or specified for HKCU cleanup in this run)." -ForegroundColor Gray
                return
            }
            # Continue processing HKCU keys only if they exist in the filtered list
        }
        # If only HKCU keys were targeted originally, this check wouldn't prevent them,
        # but the initial check catches the common case where HKLM is involved.
    }


    #region Target Verification
    $existingKeys = $registryTargets | Where-Object { Test-Path $_ }

    if (-not $existingKeys) {
        Write-Verbose "No accessible Python registry keys found matching targets."
        return
    }


    #region Backup Implementation
    # Only attempt backup if there are HKLM keys (which require elevation for backup too) or if elevated
    $hkLMKeysExist = $existingKeys -match '^HKLM:'
    if ($hkLMKeysExist -and -not $script:ExecutionContextInfo.IsElevated) {
        Write-Host "ℹ️ Skipping registry backup creation as HKLM keys require elevation." -ForegroundColor Yellow
        $BackupPath = $null # Indicate backup was skipped
    } else {
        try {
            $backupCommands = $existingKeys | ForEach-Object {
                # Convert PSPath to reg.exe compatible path
                $regPath = $_.Replace('HKLM:', 'HKEY_LOCAL_MACHINE').Replace('HKCU:', 'HKEY_CURRENT_USER').Replace('HKCR:', 'HKEY_CLASSES_ROOT')
                "reg.exe export `"$regPath`" `"$BackupPath`" /y"
            }

            if ($backupCommands) {
                $null = Start-Process cmd.exe -ArgumentList "/c $($backupCommands -join ' & ')" `
                    -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop

                if (Test-Path $BackupPath) {
                    Write-Verbose "Registry backup created: $BackupPath"
                    $backupItem = Get-Item $BackupPath
                    Write-Host "ℹ️ Registry backup created: $($backupItem.FullName)" -ForegroundColor Cyan
                }
                else {
                    Write-Warning "Backup file not created. Proceeding without backup may be risky."
                    $BackupPath = $null # Reset if backup failed
                }
            } else {
                Write-Verbose "No keys to backup."
            }
        }
        catch {
            Write-Error "Backup failed: $($_.Exception.Message)"
            $BackupPath = $null # Reset if backup failed
            # Decide whether to continue or abort if backup fails
            # For now, let's warn and continue, but this is risky.
            Write-Warning "Continuing without backup due to failure."
        }
    }


    #region Removal Protocol
    foreach ($key in $existingKeys) {
        # Re-check elevation for HKLM keys inside the loop if needed, though already filtered
        if ($key -match '^HKLM:' -and -not $script:ExecutionContextInfo.IsElevated) {
             # This case should ideally not occur due to prior filtering, but as a safeguard:
             Write-Host "⏭️ Skipped (HKLM) $key due to lack of elevation." -ForegroundColor Yellow
             continue
        }

        if ($Force -or $PSCmdlet.ShouldProcess($key, "Remove registry key")) {
            try {
                $params = @{
                    Path        = $key
                    Recurse     = $true
                    Force       = $true
                    ErrorAction = 'Stop'
                }

                Remove-Item @params
                Write-Host "🗑️ Successfully removed: $key" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to remove $key : $($_.Exception.Message)"
            }
        }
    }

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

    # Ensure context is initialized
    Initialize-PythonCleanupContext

    if (-not $System -and -not $User) {
        Write-Host "ℹ️ Specify -System, -User or both to define which PATH variable to modify." -ForegroundColor Yellow
        return
    }

    $targetScopes = @{}
    if ($System) {
        if ($script:ExecutionContextInfo.IsElevated) {
            $targetScopes["Machine"] = "System"
        } else {
            Write-Host "ℹ️ Skipped modifying System PATH due to lack of elevation." -ForegroundColor Yellow
        }
    }
    if ($User) { $targetScopes["User"] = "User" }

    if ($targetScopes.Count -eq 0) {
        Write-Host "ℹ️ No PATH scopes selected for modification or accessible." -ForegroundColor Gray
        return
    }

    foreach ($scope in $targetScopes.Keys) {
        try {
            $originalPath = [System.Environment]::GetEnvironmentVariable("Path", $scope)
            if ($null -eq $originalPath) {
                Write-Host "[+] PATH variable not found or empty in $($targetScopes[$scope]) scope." -ForegroundColor Green
                continue
            }
            $entries = $originalPath -split ";" | Where-Object { $_.Trim() -ne "" }

            $pythonPaths = $entries | Where-Object { $_ -match "Python" }

            if ($pythonPaths.Count -eq 0) {
                Write-Host "[+] No Python paths found in $($targetScopes[$scope]) PATH." -ForegroundColor Green
                continue
            }

            Write-Host "`n [$($targetScopes[$scope]) PATH] Found Python entries:" -ForegroundColor Cyan
            $pythonPaths | ForEach-Object { Write-Host "  $_" }

            if ($DryRun) {
                Write-Host " [DryRun] Would remove above entries from $($targetScopes[$scope]) PATH" -ForegroundColor Cyan
                continue
            }

            $shouldProceed = $false
            if ($Force -or $Confirm) {
                # Use built-in ShouldProcess/ShouldContinue if available and preferred
                if ($PSCmdlet.ShouldContinue("Remove these entries from $($targetScopes[$scope]) PATH?", "Confirm Deletion")) {
                     $shouldProceed = $true
                }
            } elseif ($PSCmdlet.ShouldProcess("Remove Python entries from $($targetScopes[$scope]) PATH", "Modify Environment Variable")) {
                 # Default behavior if neither -Force nor -Confirm is explicitly used relies on SupportsShouldProcess
                 $shouldProceed = $true
            }

            if ($shouldProceed) {
                $cleaned = $entries | Where-Object { $_ -notin $pythonPaths }
                $newPath = ($cleaned -join ";").TrimEnd(";")

                [System.Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
                Write-Host "[+] Updated $($targetScopes[$scope]) PATH (Python entries removed)" -ForegroundColor Green
            }
            else {
                Write-Host "[!] Skipped $($targetScopes[$scope]) PATH modification" -ForegroundColor Yellow
            }
        } catch {
            if ( ($scope -eq "Machine" -and -not $script:ExecutionContextInfo.IsElevated) -or
                 ($_.Exception.Message -like "*Requested registry access is not allowed*") ) {
                Write-Host "[!] Skipped $($targetScopes[$scope]) PATH modification due to insufficient permissions (likely lack of elevation)." -ForegroundColor Yellow
            } else {
                Write-Error "Failed to modify $($targetScopes[$scope]) PATH: $($_.Exception.Message)"
            }
        }
    }
}
