# src\core\Snapshot.ps1

class AssociationSnapshot {
    [string]$Extension

    # Indicates whether any registry data was found
    [bool]$HasData = $false

    # Holds the raw registry values we capture
    [object]$RegistryValues = [PSCustomObject]@{
        UserChoice    = $null
        SystemDefault = $null
        OpenWithList  = $null
    }

    # Mapping from the 'a'..'z' keys to resolved handler paths
    # Populated externally by the handler-resolution logic
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

    # Normalize extension to lowercase to match registry key format
    $snapshot.Extension = $Extension.ToLower()

    # Capture user-level choice if present
    try {
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($snapshot.Extension)\UserChoice"
        if (Test-Path $userChoicePath) {
            $snapshot.RegistryValues.UserChoice = Get-ItemProperty $userChoicePath
            $snapshot.HasData = $true
        }
    }
    catch {
        # Access issues ignored; consider logging if needed
    }

    # Capture system default ProgID; use Get-Item/GetValue to avoid brittle '(default)' property
    try {
        $key = Get-Item "HKCR:\$($snapshot.Extension)" -ErrorAction Stop
        $snapshot.RegistryValues.SystemDefault = $key.GetValue('')
        $snapshot.HasData = $true
    }
    catch {
        # Key may not exist or be inaccessible
    }

    # Capture the "Open With" list entries at user level
    try {
        $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($snapshot.Extension)\OpenWithList"
        if (Test-Path $openWithPath) {
            $snapshot.RegistryValues.OpenWithList = Get-ItemProperty $openWithPath
            $snapshot.HasData = $true
        }
    }
    catch {
        # Access issues ignored; consider logging if needed
    }

    return $snapshot
}
