# src\core\Repair.ps1

function Invoke-SafeClean {
    <#
        .SYNOPSIS
            Cleans ghost file-association handlers for a given extension.

        .DESCRIPTION
            Removes dead handlers from the current user's OpenWithList and repairs
            the MRUList so it no longer references the deleted entries.

            Removing a handler value without fixing MRUList leaves a dangling
            reference, which Windows never cleans up on its own - the extension
            stays in a corrupted state and re-running the tool finds nothing
            left to do. Both steps are now performed together.

            Supports dry-run preview, optional registry backup, forceful execution
            in non-interactive contexts, and verbose instrumentation.

        .PARAMETER Map
            An [AssociationSnapshot] object describing the extension and its handlers.

        .PARAMETER Diagnosis
            An [AssociationDiagnosis] object containing the results of the health check.
            Used to identify which specific handlers are considered broken.

        .PARAMETER Force
            Bypasses the interactive confirmation prompt. This does NOT weaken
            backup handling - a failed backup still aborts the cleanup.

        .PARAMETER AllowBackupFailure
            Continues the cleanup even when the registry backup failed. This is
            a separate opt-in from -Force, so that skipping the confirmation
            prompt can never silently disable backup protection.

    .PARAMETER DryRun
        Shows the planned Remove-ItemProperty commands without executing them.

    .PARAMETER Quiet
        Suppresses the preview output. Used when the caller is emitting a
        machine-readable document, where the preview text would corrupt
        stdout.

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
        [switch]$AllowBackupFailure,
        [switch]$DryRun,
        [switch]$Quiet,
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
        if (-not $Quiet) {
            Write-Information "[>] Simulated repair operations for extension '$($Map.Extension)':" -InformationAction Continue
            if ($ghostKeys.Count -eq 0) {
                 Write-Information "    No broken handlers found to remove." -InformationAction Continue
            } else {
                $ghostKeys | ForEach-Object {
                    Write-Information "    would remove handler key: $_" -InformationAction Continue
                }

                # Preview the MRUList rewrite that goes with it.
                $currentMru = Get-MruListForRepair -Map $Map -OpenWithPath $openWithPath

                if ($currentMru) {
                    $corrected = Get-CorrectedMruList -CurrentMruList $currentMru -RemovedKeys $ghostKeys
                    if ($corrected -ne $currentMru) {
                        if ([string]::IsNullOrEmpty($corrected)) {
                            Write-Information "    would remove MRUList (every referenced handler is being deleted)" -InformationAction Continue
                        }
                        else {
                            Write-Information "    would rewrite MRUList: '$currentMru' -> '$corrected'" -InformationAction Continue
                        }
                    }
                }
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
        # Track failure via an explicit flag instead of relying on exception
        # propagation alone: Backup-RegistryState catches its own errors and
        # RETURNS $false rather than throwing, so a bare try/catch would let a
        # failed backup slip through silently and clean without one.
        $backupOk = $false
        $backupErr = $null
        try {
            # Pass the extension and the custom BackupPath to Backup-RegistryState
            $result = Backup-RegistryState -ext $Map.Extension -BackupPath $BackupPath -ErrorAction Stop
            # Treat anything other than an explicit success as a failure.
            $backupOk = [bool]$result
        }
        catch {
            $backupErr = $_.Exception.Message
        }

        if (-not $backupOk) {
            $msg = if ($backupErr) { "[!] Backup failed: $backupErr" }
                   else             { "[!] Backup failed: Backup-RegistryState reported failure (no backup file written)." }
            if ($AllowBackupFailure) {
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
        else {
            Write-Verbose "[>] Registry backup completed to '$BackupPath'."
        }
    }

    # --- Perform Cleanup ---
    if ($ghostKeys.Count -eq 0) {
        Write-Verbose "[>] No broken handlers found for extension '$($Map.Extension)'. Nothing to remove."
        return
    }

    # Track which keys were actually removed. Only those may be dropped from
    # MRUList - dropping a letter whose value survived would break a working
    # association.
    $removedKeys = @()

    foreach ($handlerKey in $ghostKeys) {
        try {
            # Remove the specific registry property (e.g., 'a', 'b') from OpenWithList
            Remove-ItemProperty -Path $openWithPath -Name $handlerKey -ErrorAction Stop
            $removedKeys += $handlerKey
            Write-Verbose "[>] Successfully removed broken handler key '$handlerKey' for extension '$($Map.Extension)'."
        }
        catch {
            # Use Write-Error for failures within the loop to indicate partial failure
            Write-Error "[!] Failed to remove handler key '$handlerKey' for extension '$($Map.Extension)': $($_.Exception.Message)"
            # Depending on desired behavior, you might want to continue or break/return here
            # For now, continue trying to remove other ghosts
        }
    }

    # --- Repair MRUList ---
    # Removing a handler without fixing MRUList leaves a letter that points at
    # a value that no longer exists. Windows preserves that dangling
    # reference indefinitely, so the extension stays broken and the tool can
    # never report it as clean.
    if ($removedKeys.Count -gt 0) {
        $currentMru = Get-MruListForRepair -Map $Map -OpenWithPath $openWithPath

        if ($currentMru) {
            $corrected = Update-MruList -OpenWithPath $openWithPath `
                                        -CurrentMruList $currentMru `
                                        -RemovedKeys $removedKeys `
                                        -Confirm:$false
            Write-Verbose "[>] MRUList for extension '$($Map.Extension)' is now '$corrected'."
        }
    }
}


