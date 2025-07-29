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
    # The HandlerPaths dictionary contains successfully resolved handlers.
    # Ghosts are the handler *keys* (like 'a', 'b') associated with BrokenHandlerPath evidence.
    $brokenHandlerEvidence = $Diagnosis.Evidence | Where-Object { $_.State -eq [AssociationState]::BrokenHandlerPath }
    # Extract the handler keys (e.g., 'a', 'b') from the descriptive message.
    # This assumes the message format is consistent, e.g., "Handler resolution failed: <keyname>"
    # A more robust way would be to pass the key names directly or store them differently during diagnosis.
    # For now, we parse the key name from the message.
    $ghostKeys = $brokenHandlerEvidence | ForEach-Object {
        # Example message: "Handler resolution failed: a"
        # Extract the last part after the colon and space
        if ($_.Message -match ':\s*([a-z])$') {
            return $matches[1]
        }
    } | Where-Object { $_ } # Filter out $null results if regex fails

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
    if (-not $Force) {
        $proceed = $PSCmdlet.ShouldContinue(
            "Proceed with cleaning ghost handlers for extension '$($Map.Extension)'?",
            'Confirm Cleanup'
        )
        if (-not $proceed) {
            Write-Information "[>] Cleanup skipped by user" -InformationAction Continue
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
                Write-Warning $msg
            }
            else {
                Write-Error "[X] $msg. Aborting."; return
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