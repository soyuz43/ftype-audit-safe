# src\core\Repair.ps1

function Invoke-SafeClean {
    <#
        .SYNOPSIS
            Cleans ghost file-association handlers for a given extension.

        .DESCRIPTION
            Removes non-existent ProgID entries from the current user's OpenWithList.
            Supports dry-run preview, optional registry backup, forceful execution in
            non-interactive contexts, and verbose instrumentation.

        .PARAMETER Map
            An [AssociationSnapshot] object describing the extension and its handlers.

        .PARAMETER Diagnosis
            An [AssociationDiagnosis] object containing the results of the health check.
            Used to identify which specific handlers are considered broken.

        .PARAMETER Force
            Bypasses interactive confirmation and continues despite backup failures.

        .PARAMETER DryRun
            Shows the planned Remove-ItemProperty commands without executing them.

        .PARAMETER Backup
            Creates a backup of the relevant registry branch before modification.

        .PARAMETER BackupPath
            Specifies the path for the registry backup file.
            Defaults to a timestamped file in the current directory.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Map,

        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationDiagnosis]$Diagnosis,

        [switch]$Force,
        [switch]$DryRun,
        [switch]$Backup,
        [string]$BackupPath = ".\ftype-backup-$(Get-Date -Format yyyyMMdd-HHmmss).reg" # Add BackupPath parameter
    )

    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Map.Extension)\OpenWithList"

    # --- Identify ghost handlers based on Diagnosis ---
    # Test-AssociationHealth records the exact OpenWithList keys (e.g. 'a', 'b')
    # whose handler values failed to resolve in Diagnosis.BrokenHandlerKeys.
    # We consume that structured data directly — no message parsing required.
    $ghostKeys = @($Diagnosis.BrokenHandlerKeys)

    # --- Dry-Run Preview ---
    if ($DryRun) {
        Write-Information "[>] Simulated repair operations for extension '$($Map.Extension)':" -InformationAction Continue
        if ($ghostKeys.Count -eq 0) {
             Write-Information "    No broken handlers found to remove." -InformationAction Continue
        } else {
            $ghostKeys | ForEach-Object {
                Write-Information "    would remove handler key: $_" -InformationAction Continue
                # In a real dry-run, you might show the specific Remove-ItemProperty command
                # Write-Information "    Remove-ItemProperty -Path $openWithPath -Name $_" -InformationAction Continue
            }
        }
        return
    }

    # --- ShouldProcess Gate ---
    if (-not $PSCmdlet.ShouldProcess($Map.Extension, 'Modify registry associations')) {
        return
    }

    # --- Interactive Confirmation ---
    # Only prompt when the caller has NOT suppressed confirmation. Passing
    # -Confirm:$false is an explicit opt-out (used by automation and tests);
    # otherwise ask interactively, falling back to a warning + abort in
    # non-interactive hosts where ShouldContinue() would throw a
    # NullReferenceException due to a null internal UI object.
    $confirmRequested = -not $PSBoundParameters.ContainsKey('Confirm') -or $PSBoundParameters['Confirm']

    if (-not $Force -and $confirmRequested) {
        if ([Environment]::UserInteractive -and $Host.UI.RawUI) {
            $proceed = $PSCmdlet.ShouldContinue(
                "Proceed with cleaning ghost handlers for extension '$($Map.Extension)'?",
                'Confirm Cleanup'
            )
            if (-not $proceed) {
                Write-Information "[>] Cleanup skipped by user" -InformationAction Continue
                return
            }
        }
        else {
            Write-Warning "Non-interactive session detected: confirmation prompt unavailable. Re-run with -Force to proceed."
            return
        }
    }

    # --- Optional Registry Backup ---
    if ($Backup) {
        try {
            # Pass the extension and the custom BackupPath to Backup-RegistryState
            Backup-RegistryState -ext $Map.Extension -BackupPath $BackupPath -ErrorAction Stop | Out-Null
            Write-Verbose "[>] Registry backup completed to '$BackupPath'."
        }
        catch {
            $msg = "[!] Backup failed: $($_.Exception.Message)"
            if ($Force) {
                # Caller explicitly opted into risky cleanup: warn and continue.
                Write-Warning $msg
            }
            else {
                # Throw (not Write-Error) so the abort is terminating regardless
                # of the caller's global ErrorActionPreference; callers that want
                # to tolerate this should wrap the invocation in try/catch.
                throw "[X] $msg Aborting."
            }
        }
    }

    # --- Perform Cleanup ---
    if ($ghostKeys.Count -eq 0) {
        Write-Verbose "[>] No broken handlers found for extension '$($Map.Extension)'. Nothing to remove."
        return
    }

    foreach ($handlerKey in $ghostKeys) {
        try {
            # Remove the specific registry property (e.g., 'a', 'b') from OpenWithList
            Remove-ItemProperty -Path $openWithPath -Name $handlerKey -ErrorAction Stop
            Write-Verbose "[>] Successfully removed broken handler key '$handlerKey' for extension '$($Map.Extension)'."
        }
        catch {
            # Use Write-Error for failures within the loop to indicate partial failure
            Write-Error "[!] Failed to remove handler key '$handlerKey' for extension '$($Map.Extension)': $($_.Exception.Message)"
            # Depending on desired behavior, you might want to continue or break/return here
            # For now, continue trying to remove other ghosts
        }
    }
}