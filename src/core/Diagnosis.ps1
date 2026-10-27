# src\core\Diagnosis.ps1

# --- Type definitions ---------------------------------------
enum AssociationState {
    MissingUserChoice
    InvalidProgIdSyntax
    UnregisteredProgId
    BrokenHandlerPath
    InertHandlerPath
    CorruptMRUOrder
}

class AssociationDiagnosis {
    [System.Collections.Generic.List[PSCustomObject]]$Evidence

    # Machine-readable list of OpenWithList keys (e.g. 'a', 'e') whose handler
    # values could not be resolved. Populated during Phase 3 of the health check
    # so repair logic never has to parse human-readable messages.
    [System.Collections.Generic.List[string]]$BrokenHandlerKeys

    # Handlers that resolve to a live registration but cannot actually open a
    # document (registered with no 'open' verb). These are reported but are
    # deliberately NOT treated as broken, because Explorer owns them and would
    # simply re-create them.
    [System.Collections.Generic.List[string]]$InertHandlerKeys

    AssociationDiagnosis() {
        # Initialize an empty list to hold state/message entries
        $this.Evidence = [System.Collections.Generic.List[PSCustomObject]]::new()
        $this.BrokenHandlerKeys = [System.Collections.Generic.List[string]]::new()
        $this.InertHandlerKeys = [System.Collections.Generic.List[string]]::new()
    }

    [void] RegisterState([AssociationState]$State, [string]$Message) {
        # Append a new evidence entry
        $entry = [PSCustomObject]@{
            State   = $State
            Message = $Message
        }
        $this.Evidence.Add($entry)
    }

    [void] RegisterBrokenHandler([string]$Key, [string]$Handler, [string]$Reason) {
        # Record the broken handler both as display evidence and as a machine-usable key
        $entry = [PSCustomObject]@{
            State   = [AssociationState]::BrokenHandlerPath
            Message = "Handler resolution failed: $Handler ($Reason)"
        }
        $this.Evidence.Add($entry)
        if ($Key -and -not $this.BrokenHandlerKeys.Contains($Key)) {
            $this.BrokenHandlerKeys.Add($Key)
        }
    }

    [void] RegisterInertHandler([string]$Key, [string]$Handler, [string]$Reason) {
        # A handler that is registered but cannot open documents.
        $entry = [PSCustomObject]@{
            State   = [AssociationState]::InertHandlerPath
            Message = "Handler registered but not openable: $Handler ($Reason)"
        }
        $this.Evidence.Add($entry)
        if ($Key -and -not $this.InertHandlerKeys.Contains($Key)) {
            $this.InertHandlerKeys.Add($Key)
        }
    }

    # Derived helper: call as $diagnosis.HasIssues() — PowerShell classes do not
    # expose get_/set_ method pairs as properties the way C# does.
    [bool] HasIssues() {
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
        $userChoiceProgId = [string]$Snapshot.RegistryValues.UserChoice.ProgId
        # Validate the *shape* only. Whether the ProgID is actually registered
        # is checked in Phase 2 - a shape check alone rejected legitimate
        # hyphenated ProgIDs such as 'FirefoxPDF-CA9422711AE1A81C'.
        if ($userChoiceProgId -notmatch '^[\w.\-]+$') {
            $diagnosis.RegisterState(
                [AssociationState]::InvalidProgIdSyntax,
                "ProgID format violation: $userChoiceProgId"
            )
        }
    }

    # Phase 2: Semantic validation
    if ($Snapshot.RegistryValues.SystemDefault) {
        $systemProgId = $Snapshot.RegistryValues.SystemDefault
        # Note: the "HKCR:" PSDrive is not mounted in PowerShell 7 on this
        # platform, so Test-Path "HKCR:\..." silently returned $false for every
        # ProgID. The merged view is reached via the provider path instead.
        if (-not (Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\$systemProgId")) {
            $diagnosis.RegisterState(
                [AssociationState]::UnregisteredProgId,
                "System default ProgID not registered: $systemProgId"
            )
        }
    }

    # Phase 3: Handler verification
    #
    # Resolution is delegated to Resolve-OpenWithListHandlers, which follows
    # the shell's own lookup chain (App Paths, Applications, ProgID, AppX).
    # The previous inline implementation used only Test-Path and Get-Command,
    # which misclassified every installed-but-not-on-PATH application as
    # broken.
    $resolutions = Resolve-OpenWithListHandlers -Snapshot $Snapshot

    foreach ($key in @($resolutions.Keys | Sort-Object)) {
        $resolution = $resolutions[$key]

        # Note: an if/elseif chain is used deliberately here. A `switch` with
        # enum case labels does not compare by value - it compares the enum
        # object against the case, so every branch fell through to `default`.
        if ($resolution.Status -eq [HandlerResolution]::Resolved) {
            $Snapshot.HandlerPaths[$key] = $resolution.ResolvedPath
        }
        elseif ($resolution.Status -eq [HandlerResolution]::NotOpenable) {
            # Registered, but cannot open a document. Reported for
            # visibility, never handed to the repair step.
            $diagnosis.RegisterInertHandler($key, $resolution.Handler, $resolution.Detail)
        }
        else {
            # NotRegistered, TargetMissing, Malformed - these are the
            # entries the repair step is allowed to remove.
            $diagnosis.RegisterBrokenHandler($key, $resolution.Handler, $resolution.Detail)
        }
    }

    # Phase 4: MRU coherence check
    #
    # A MRU letter is invalid when it points at a handler we know is broken,
    # or when it references a letter with no OpenWithList value at all. The
    # latter is the dangling-reference case the repair step must also fix.
    $mru = $Snapshot.RegistryValues.OpenWithList.MRUList
    if ($mru) {
        $mruChars = $mru -replace '[^a-z]', ''

        $invalidRefs = $mruChars.ToCharArray() | Where-Object {
            $letter = $_.ToString()
            if ($diagnosis.BrokenHandlerKeys.Contains($letter)) {
                return $true
            }
            if ($diagnosis.InertHandlerKeys.Contains($letter)) {
                return $false
            }
            # Not in HandlerPaths and not registered as inert => no value.
            return -not $Snapshot.HandlerPaths.ContainsKey($letter)
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


