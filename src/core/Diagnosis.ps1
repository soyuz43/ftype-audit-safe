# src\core\Diagnosis.ps1

# --- Type definitions ---------------------------------------
enum AssociationState {
    MissingUserChoice
    InvalidProgIdSyntax
    UnregisteredProgId
    BrokenHandlerPath
    CorruptMRUOrder
}

class AssociationDiagnosis {
    [System.Collections.Generic.List[PSCustomObject]]$Evidence

    AssociationDiagnosis() {
        # Initialize an empty list to hold state/message entries
        $this.Evidence = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    [void] RegisterState([AssociationState]$State, [string]$Message) {
        # Append a new evidence entry
        $entry = [PSCustomObject]@{
            State   = $State
            Message = $Message
        }
        $this.Evidence.Add($entry)
    }

    [bool] get_HasIssues() {
        return ($this.Evidence.Count -gt 0)
    }
}

# --- Main diagnostic function ------------------------------
function Test-AssociationHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AssociationSnapshot]$Snapshot
    )

    # Instantiate a diagnosis object
    $diagnosis = [AssociationDiagnosis]::new()

    # Ensure HandlerPaths dictionary exists on snapshot
    if (-not $Snapshot.HandlerPaths) {
        $Snapshot.HandlerPaths = [System.Collections.Generic.Dictionary[string,string]]::new()
    }

    # Phase 1: Structural validation
    if (-not $Snapshot.RegistryValues.UserChoice) {
        $diagnosis.RegisterState(
            [AssociationState]::MissingUserChoice,
            "No UserChoice key found for extension"
        )
    }
    else {
        if ($Snapshot.RegistryValues.UserChoice.ProgId -notmatch '^(AppX[\w]+|\w+(\.\w+)*)$') {
            $diagnosis.RegisterState(
                [AssociationState]::InvalidProgIdSyntax,
                "ProgID format violation: $($Snapshot.RegistryValues.UserChoice.ProgId)"
            )
        }
    }

    # Phase 2: Semantic validation
    if ($Snapshot.RegistryValues.SystemDefault) {
        $systemProgId = $Snapshot.RegistryValues.SystemDefault
        if (-not (Test-Path "HKCR:\$systemProgId")) {
            $diagnosis.RegisterState(
                [AssociationState]::UnregisteredProgId,
                "System default ProgID not registered: $systemProgId"
            )
        }
    }

    # Phase 3: Handler verification
    $openList = $Snapshot.RegistryValues.OpenWithList
    if ($openList) {
        # Extract entries named 'a'..'z'
        $entries = $openList.psobject.Properties | Where-Object { $_.Name -match '^[a-z]$' }
        foreach ($prop in $entries) {
            $handler = $prop.Value -replace '^"(.*)"$', '$1'

            if (Test-Path $handler) {
                $Snapshot.HandlerPaths[$prop.Name] = $handler
            }
            else {
                try {
                    $resolved = (Get-Command $handler -ErrorAction Stop).Source
                    $Snapshot.HandlerPaths[$prop.Name] = $resolved
                }
                catch {
                    $diagnosis.RegisterState(
                        [AssociationState]::BrokenHandlerPath,
                        "Handler resolution failed: $handler"
                    )
                }
            }
        }
    }

    # Phase 4: MRU coherence check
    $mru = $Snapshot.RegistryValues.OpenWithList.MRUList
    if ($mru) {
        $mruChars = $mru -replace '[^a-z]', ''
        $invalidRefs = $mruChars.ToCharArray() | Where-Object {
            -not $Snapshot.HandlerPaths.ContainsKey($_)
        }

        if ($invalidRefs) {
            $diagnosis.RegisterState(
                [AssociationState]::CorruptMRUOrder,
                "MRU references invalid handlers: $($invalidRefs -join ',')"
            )
        }
    }

    return $diagnosis
}
