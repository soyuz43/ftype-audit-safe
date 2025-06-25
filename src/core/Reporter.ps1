# src\core\Reporter.ps1

#  Helper: Resolve a ProgID like 'AppX...' to a friendly app name (e.g., "Notepad")
function Resolve-ProgIdToAppName {
    param ([string]$ProgId)

    if (-not $ProgId) {
        return '<not set>'
    }

    try {
        # Try to get the friendly name from the registry
        $regPath = "HKEY_CLASSES_ROOT\$ProgId"
        $friendlyName = (Get-ItemProperty -Path "Registry::$regPath" -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
        
        if ($friendlyName) {
            return "$ProgId ($friendlyName)"
        } else {
            return "$ProgId (No description)"
        }
    } catch {
        return "$ProgId (Unresolvable)"
    }
}

function Show-AssociationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Snapshot,

        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationDiagnosis]$Diagnosis
    )

    foreach ($state in $Diagnosis.ActiveStates) {
        Write-Information "  $state" -InformationAction Continue
    }
    # Header
    Write-Information "`nAssociation Health Report: $($Snapshot.Extension)" -InformationAction Continue
    Write-Information ("Captured at: {0:yyyy-MM-dd HH:mm:ss}" -f $Snapshot.LastChecked) -InformationAction Continue

    # States
    Write-Information "`n[States]" -InformationAction Continue
    foreach ($state in $Diagnosis.ActiveStates) {
        Write-Information "  $state" -InformationAction Continue
    }

    # Evidence
    Write-Information "`n[Evidence]" -InformationAction Continue
    foreach ($e in $Diagnosis.Evidence) {
        Write-Information "  $e" -InformationAction Continue
    }
}

function Write-AssociationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot] $Snapshot,

        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationDiagnosis] $Diagnosis,

        [Parameter()][ValidateSet("Literal", "Explain", "Summary", "None")]
        [string] $Mode = "Summary",

        [hashtable] $ColorScheme = @{
            Success   = 'Green'
            Warning   = 'Red'
            Detail    = 'Yellow'
            Header    = 'Cyan'
            Timestamp = 'DarkGray'
        }
    )

    if (-not $Snapshot -or -not $Diagnosis) {
        throw "Invalid input: Snapshot and Diagnosis must be provided"
    }

    # Build a lookup for quick state checks
    $stateTable = @{}
    foreach ($s in $Diagnosis.ActiveStates) { $stateTable[$s] = $true }

    switch ($Mode) {
        'None' { return }

        'Literal' {
            Show-AssociationReport -Snapshot $Snapshot -Diagnosis $Diagnosis
        }

        'Explain' {
            Write-Information "`n[EXPLAINED VIEW: $($Snapshot.Extension.ToUpper())]" -InformationAction Continue
            Write-Information ("Timestamp: {0}" -f $Snapshot.LastChecked.ToString('yyyy-MM-dd HH:mm')) -InformationAction Continue

            Write-Information "`nCORE STATUS:" -InformationAction Continue
            if ($Diagnosis.ActiveStates.Count -eq 0) {
                Write-Information "[+] Configuration Valid" -InformationAction Continue
            }
            else {
                Write-Warning "[!] Configuration Issues:" 
                foreach ($s in $Diagnosis.ActiveStates) {
                    Write-Information ("  - {0}" -f $s) -InformationAction Continue
                }
            }

            Write-Information "`nREGISTRY ANALYSIS:" -InformationAction Continue

            $resolved = Resolve-ProgIdToAppName $Snapshot.RegistryValues.UserChoice?.ProgId
            Write-Information ("User Choice:    {0}" -f ($resolved ?? '<not set>')) -InformationAction Continue
            Write-Information ("System Default: {0}" -f ($Snapshot.RegistryValues.SystemDefault ?? '<undefined>')) -InformationAction Continue
            Write-Information ("Valid Handlers: {0}" -f $Snapshot.HandlerPaths.Count) -InformationAction Continue
            $mruStatus = if ($stateTable[[AssociationState]::CorruptMRUOrder]) { 'Compromised' } else { 'Intact' }
            Write-Information ("MRU Integrity:  {0}" -f $mruStatus) -InformationAction Continue
        }

        'Summary' {
            $status = if ($Diagnosis.ActiveStates.Count -eq 0) {
                "[+]"
            } else {
                "[!] {0} issue(s)" -f $Diagnosis.ActiveStates.Count
            }
            Write-Information ("{0}: {1}" -f $Snapshot.Extension.PadRight(8), $status) -InformationAction Continue

            # Legend for summary symbols
            Write-Information "" -InformationAction Continue
            Write-Information 'Legend:' -InformationAction Continue
            Write-Information '  [+]  All association checks passed successfully.' -InformationAction Continue
            Write-Information '  [!]  One or more issues detected — run with -Explain for details.' -InformationAction Continue
        }
    }
}
