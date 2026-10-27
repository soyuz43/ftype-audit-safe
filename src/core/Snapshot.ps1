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
        # This pattern must stay consistent with Get-ValidatedExtension in
        # src/ftype-audit.ps1, which uses '^\.[A-Za-z0-9](?:[\w-]{0,254})$'.
        # The two disagreed: the script accepted '.my-ext' and long
        # extensions, then the snapshot rejected them with exit code 3 and a
        # confusing parameter-validation message.
        [ValidatePattern('^\.[A-Za-z0-9][\w-]{0,254}$')]
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

    # Capture system default ProgID; use Get-Item/GetValue to avoid brittle '(default)' property.
    #
    # The merged HKEY_CLASSES_ROOT view is addressed as
    # 'Registry::HKEY_CLASSES_ROOT\...'. The 'HKCR:' PSDrive is not mounted in
    # PowerShell 7, and on this machine it is not present in Windows
    # PowerShell 5.1 either - so the old 'HKCR:\' path threw "Cannot find
    # drive" and the catch block silently swallowed it. SystemDefault was
    # therefore always empty in live runs, which quietly disabled the
    # UnregisteredProgId check in Test-AssociationHealth.
    try {
        $key = Get-Item "Registry::HKEY_CLASSES_ROOT\$($snapshot.Extension)" -ErrorAction Stop
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
