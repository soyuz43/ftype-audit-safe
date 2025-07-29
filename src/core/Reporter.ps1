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

    # Header
    Write-Information "`nAssociation Health Report: $($Snapshot.Extension)" -InformationAction Continue
    Write-Information ("Captured at: {0:yyyy-MM-dd HH:mm:ss}" -f $Snapshot.LastChecked) -InformationAction Continue

    # Evidence (This replaces the old [States] section which used non-existent ActiveStates)
    # The Evidence contains both the State enum and the descriptive Message
    Write-Information "`n[Evidence]" -InformationAction Continue
    if ($Diagnosis.Evidence.Count -eq 0) {
        Write-Information "  No issues detected." -InformationAction Continue
    } else {
        foreach ($evidenceItem in $Diagnosis.Evidence) {
            # Example output: "  CorruptMRUOrder: MRU references invalid handlers: a,e,b"
            Write-Information "  $($evidenceItem.State): $($evidenceItem.Message)" -InformationAction Continue
        }
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

    # Build a lookup for quick state checks based on Evidence
    # This is used in 'Explain' mode to check for specific states like CorruptMRUOrder
    $stateTable = @{}
    foreach ($evidenceItem in $Diagnosis.Evidence) {
        # Use the State enum value as the key for easy lookup
        $stateTable[$evidenceItem.State] = $true
        # Alternatively, if you wanted to count occurrences:
        # if (-not $stateTable.ContainsKey($evidenceItem.State)) {
        #     $stateTable[$evidenceItem.State] = 0
        # }
        # $stateTable[$evidenceItem.State]++
    }

    switch ($Mode) {
        'None' { return }

        'Literal' {
            Show-AssociationReport -Snapshot $Snapshot -Diagnosis $Diagnosis
        }

        'Explain' {
            Write-Information "`n[EXPLAINED VIEW: $($Snapshot.Extension.ToUpper())]" -InformationAction Continue
            Write-Information ("Timestamp: {0}" -f $Snapshot.LastChecked.ToString('yyyy-MM-dd HH:mm')) -InformationAction Continue

            Write-Information "`nCORE STATUS:" -InformationAction Continue
            # Use Evidence.Count instead of ActiveStates.Count
            if ($Diagnosis.Evidence.Count -eq 0) {
                Write-Information "[+] Configuration Valid" -InformationAction Continue
            }
            else {
                Write-Warning "[!] Configuration Issues:"
                # Iterate through Evidence to show issues
                foreach ($evidenceItem in $Diagnosis.Evidence) {
                     # Show the descriptive message from Evidence
                    Write-Information ("  - {0}: {1}" -f $evidenceItem.State, $evidenceItem.Message) -InformationAction Continue
                }
            }

            Write-Information "`nREGISTRY ANALYSIS:" -InformationAction Continue

            $resolved = Resolve-ProgIdToAppName $Snapshot.RegistryValues.UserChoice?.ProgId
            Write-Information ("User Choice:    {0}" -f ($resolved ?? '<not set>')) -InformationAction Continue
            Write-Information ("System Default: {0}" -f ($Snapshot.RegistryValues.SystemDefault ?? '<undefined>')) -InformationAction Continue
            Write-Information ("Valid Handlers: {0}" -f $Snapshot.HandlerPaths.Count) -InformationAction Continue
            
            # Use the stateTable (built from Evidence) to check for CorruptMRUOrder
            $mruStatus = if ($stateTable.ContainsKey([AssociationState]::CorruptMRUOrder)) { 'Compromised' } else { 'Intact' }
            Write-Information ("MRU Integrity:  {0}" -f $mruStatus) -InformationAction Continue
        }

        'Summary' {
            # Use Evidence.Count instead of ActiveStates.Count
            $status = if ($Diagnosis.Evidence.Count -eq 0) {
                "[+]"
            } else {
                "[!] {0} issue(s)" -f $Diagnosis.Evidence.Count
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