# src\core\Diagnosis.ps1
function Test-AssociationHealth {
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Snapshot
    )

    $diagnosis = [AssociationDiagnosis]::new()

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
    $Snapshot.RegistryValues.OpenWithList.GetEnumerator() | Where-Object {
        $_.Name -match '^[a-z]$'
    } | ForEach-Object {
        $handler = $_.Value -replace '^"(.*)"$', '$1'

        if (Test-Path $handler) {
            $Snapshot.HandlerPaths[$_.Name] = $handler
        }
        else {
            try {
                $resolved = (Get-Command $handler -ErrorAction Stop).Source
                $Snapshot.HandlerPaths[$_.Name] = $resolved
            }
            catch {
                $diagnosis.RegisterState(
                    [AssociationState]::BrokenHandlerPath,
                    "Handler resolution failed: $handler"
                )
            }
        }
    }

    # Phase 4: MRU coherence check
    if ($Snapshot.RegistryValues.OpenWithList.MRUList) {
        $mruChars = $Snapshot.RegistryValues.OpenWithList.MRUList -replace '[^a-z]', ''
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
