# src\core\Snapshot.ps1

class AssociationSnapshot {
    [string]$Extension

    # Holds the raw registry values we capture
    [object]$RegistryValues = [PSCustomObject]@{
        UserChoice    = $null
        SystemDefault = $null
        OpenWithList  = $null
    }

    # Mapping from the 'a'..'z' keys to resolved handler paths
    [System.Collections.Generic.Dictionary[string,string]]$HandlerPaths

    # When this snapshot was taken
    [datetime]$LastChecked

    AssociationSnapshot() {
        # Initialize an empty handler map
        $this.HandlerPaths = [System.Collections.Generic.Dictionary[string,string]]::new()

        # Record the timestamp for reporting
        $this.LastChecked = Get-Date
    }
}

function Get-AssociationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\.[a-z0-9]{1,10}$')]
        [string]$Extension
    )

    # Build a fresh snapshot object
    $snapshot = [AssociationSnapshot]::new()
    $snapshot.Extension = $Extension.ToLower()

    # Capture raw registry state
    try {
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        if (Test-Path $userChoicePath) {
            $snapshot.RegistryValues.UserChoice = Get-ItemProperty $userChoicePath
        }
    }
    catch {
        # Log access issues if you wire up a logger
    }

    try {
        $snapshot.RegistryValues.SystemDefault = (Get-ItemProperty "HKCR:\$Extension" -ErrorAction Stop).'(default)'
    }
    catch {
        # Key may not exist
    }

    try {
        $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithList"
        if (Test-Path $openWithPath) {
            $snapshot.RegistryValues.OpenWithList = Get-ItemProperty $openWithPath
        }
    }
    catch {
        # Log access issues if desired
    }

    return $snapshot
}
