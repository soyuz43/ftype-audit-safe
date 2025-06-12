# src\core\Snapshot.ps1

function Get-AssociationSnapshot {
    param(
        [Parameter(Mandatory)][ValidatePattern('^\.[a-z0-9]{1,10}$')]
        [string]$Extension
    )

    $snapshot = [AssociationSnapshot]::new()
    $snapshot.Extension = $Extension.ToLower()

    # Capture raw registry state
    try {
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        if (Test-Path $userChoicePath) {
            $snapshot.RegistryValues.UserChoice = Get-ItemProperty $userChoicePath
        }
    }
    catch { /* Log access issues */ }

    try {
        $snapshot.RegistryValues.SystemDefault = (Get-ItemProperty "HKCR:\$Extension" -ErrorAction Stop).'(default)'
    }
    catch { /* Log missing key */ }

    try {
        $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithList"
        if (Test-Path $openWithPath) {
            $snapshot.RegistryValues.OpenWithList = Get-ItemProperty $openWithPath
        }
    }
    catch { /* Log access issues */ }

    return $snapshot
}
