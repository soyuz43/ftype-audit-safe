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

        .PARAMETER Force
            Bypasses interactive confirmation and continues despite backup failures.

        .PARAMETER DryRun
            Shows the planned Remove-ItemProperty commands without executing them.

        .PARAMETER Backup
            Creates a backup of the relevant registry branch before modification.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Map,

        [switch]$Force,
        [switch]$DryRun,
        [switch]$Backup
    )

    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Map.Extension)\OpenWithList"

    # Identify handlers whose executable path no longer exists
    $ghosts = $Map.Handlers.GetEnumerator() | Where-Object { -not $_.Value.Exists }

    # ── Dry-Run Preview ─────────────────────────────────────────────────────────
    if ($DryRun) {
        Write-Information "[>] Planned operations for extension '$($Map.Extension)'" -InformationAction Continue
        $ghosts | ForEach-Object {
            Write-Information "    Remove-ItemProperty -Path $openWithPath -Name $($_.Key)" -InformationAction Continue
        }
        return
    }

    # ── ShouldProcess Gate ──────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess($Map.Extension, 'Modify registry associations')) {
        return
    }

    # ── Interactive Confirmation ───────────────────────────────────────────────
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

    # ── Optional Registry Backup ───────────────────────────────────────────────
    if ($Backup) {
        try {
            Backup-RegistryState $Map.Extension -ErrorAction Stop | Out-Null
            Write-Verbose "[>] Registry backup completed."
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

    # ── Perform Cleanup ─────────────────────────────────────────────────────────
    foreach ($handler in $ghosts) {
        try {
            Remove-ItemProperty -Path $openWithPath -Name $handler.Key -ErrorAction Stop
            Write-Verbose "[>] Removed handler '$($handler.Key)'"
        }
        catch {
            Write-Warning "[!] Failed to remove handler '$($handler.Key)': $($_.Exception.Message)"
        }
    }
}