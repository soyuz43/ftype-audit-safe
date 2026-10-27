# src\core\JsonOutput.ps1
# Emits machine-readable JSON for automation and CI gating.
#
# The human-readable report modes (Summary / Explain / Literal) are written to
# the Information stream, which makes them awkward to consume from a script:
# the output is prose, and it is interleaved with warnings and elevation
# notices. This module produces a stable, documented JSON document instead.
#
# Schema stability notes:
#
#   * Every object carries a 'schemaVersion'. Consumers can branch on it
#     rather than guessing. The current version is 1.
#   * Enum values are emitted as their string names, not their ordinals, so
#     the output survives a reordering of the underlying enum.
#   * Property names are camelCase and are not localized.
#
# The document is built as plain hashtables and then serialized with
# ConvertTo-Json. PowerShell's serializer handles enum values inconsistently
# across versions, so the enum members are converted to strings explicitly
# before serialization rather than relying on the default behavior.

# The JSON schema version emitted by this module. Bump this when the shape of
# the document changes in a way that is not purely additive.
$script:JsonSchemaVersion = 1

<#
.SYNOPSIS
Returns the current JSON schema version.

.DESCRIPTION
Automation consumers can call this to check what they are parsing against
without having to hard-code the number.
#>
function Get-JsonSchemaVersion {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    return $script:JsonSchemaVersion
}

<#
.SYNOPSIS
Converts an enum value to its string name.

.DESCRIPTION
ConvertTo-Json serializes enums inconsistently between PowerShell versions.
Resolving the name explicitly keeps the JSON output stable.
#>
function ConvertTo-EnumName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    # Already a string (or something without a type).
    if ($Value -is [string]) {
        return $Value
    }

    try {
        return $Value.ToString()
    }
    catch {
        return [string]$Value
    }
}

<#
.SYNOPSIS
Builds the JSON document for a single extension's audit result.

.DESCRIPTION
Produces the audit portion of the document. The result contains the snapshot
summary, the diagnosis evidence, and the resolved state of each OpenWithList
handler.

.PARAMETER Snapshot
The AssociationSnapshot that was captured.

.PARAMETER Diagnosis
The AssociationDiagnosis produced from that snapshot.

.PARAMETER Resolutions
Optional hashtable of handler key to HandlerResolutionResult, as returned by
Resolve-OpenWithListHandlers.
#>
function New-AuditJsonDocument {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [object]$Snapshot,

        [Parameter(Mandatory)][ValidateNotNull()]
        [object]$Diagnosis,

        [Parameter()][AllowNull()]
        [hashtable]$Resolutions
    )

    # --- Handler detail -------------------------------------------------
    $handlers = @()
    if ($Resolutions) {
        foreach ($key in ($Resolutions.Keys | Sort-Object)) {
            $resolution = $Resolutions[$key]
            $handlers += [ordered]@{
                key          = $key
                handler      = $resolution.Handler
                status       = ConvertTo-EnumName $resolution.Status
                resolvedPath = $resolution.ResolvedPath
                method       = $resolution.Method
                detail       = $resolution.Detail
                isBroken     = ($resolution.Status -ne [HandlerResolution]::Resolved -and
                                $resolution.Status -ne [HandlerResolution]::NotOpenable)
            }
        }
    }

    # --- Evidence -------------------------------------------------------
    $evidence = @()
    foreach ($item in $Diagnosis.Evidence) {
        $evidence += [ordered]@{
            state   = ConvertTo-EnumName $item.State
            message = $item.Message
        }
    }

    $brokenKeys = @($Diagnosis.BrokenHandlerKeys | Sort-Object)
    $inertKeys  = @($Diagnosis.InertHandlerKeys | Sort-Object)

    # --- Snapshot summary ------------------------------------------------
    $userChoiceProgId = $null
    if ($Snapshot.RegistryValues.UserChoice) {
        $userChoiceProgId = $Snapshot.RegistryValues.UserChoice.ProgId
    }

    $mruList = ''
    $openWithValues = [ordered]@{}
    if ($Snapshot.RegistryValues.OpenWithList) {
        $mruList = [string]$Snapshot.RegistryValues.OpenWithList.MRUList
        # Get-ItemProperty returns a PSObject that carries provider metadata
        # alongside the real registry values (PSPath, PSDrive, PSParentPath,
        # PSChildName, PSProvider, and the rest). Emitting those into the
        # document would leak internal PowerShell plumbing into the public
        # schema, so only the genuine registry values are kept.
        foreach ($property in $Snapshot.RegistryValues.OpenWithList.PSObject.Properties) {
            # Skip provider metadata.
            if ($property.Name -like 'PS*') { continue }
            if ($property.Name -eq 'MRUList') { continue }
            $openWithValues[$property.Name] = [string]$property.Value
        }
    }

    $document = [ordered]@{
        schemaVersion   = $script:JsonSchemaVersion
        extension       = $Snapshot.Extension
        capturedAt      = $Snapshot.LastChecked.ToString('o')
        healthy         = ($Diagnosis.Evidence.Count -eq 0)
        issueCount      = $Diagnosis.Evidence.Count
        registry        = [ordered]@{
            userChoiceProgId = $userChoiceProgId
            systemDefault    = $Snapshot.RegistryValues.SystemDefault
            mruList          = $mruList
            openWithList     = $openWithValues
        }
        handlers        = $handlers
        evidence        = $evidence
        brokenHandlers  = $brokenKeys
        inertHandlers   = $inertKeys
    }

    return $document
}

<#
.SYNOPSIS
Adds a repair plan to an existing audit document.

.DESCRIPTION
The plan describes what the repair step would do, without performing it.
This is what makes a dry run machine-checkable: a consumer can compare the
planned removals against the actual result.

.PARAMETER Document
The document produced by New-AuditJsonDocument.

.PARAMETER PlannedRemovals
The OpenWithList keys that would be removed.

.PARAMETER CurrentMruList
The MRUList value as it stands.

.PARAMETER PlannedMruList
The MRUList value after the repair.

.PARAMETER Applied
Whether the repair was actually performed.
#>
function Add-RepairPlanToJsonDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [System.Collections.IDictionary]$Document,

        [Parameter()][AllowEmptyCollection()]
        [string[]]$PlannedRemovals = @(),

        [Parameter()][AllowNull()][AllowEmptyString()]
        [string]$CurrentMruList = '',

        [Parameter()][AllowNull()][AllowEmptyString()]
        [string]$PlannedMruList = '',

        [Parameter()]
        [switch]$Applied
    )

    $Document['repair'] = [ordered]@{
        applied           = [bool]$Applied
        plannedRemovals   = @($PlannedRemovals)
        currentMruList    = $CurrentMruList
        plannedMruList    = $PlannedMruList
        mruListWillChange = ($CurrentMruList -ne $PlannedMruList)
    }

    return $Document
}

<#
.SYNOPSIS
Serializes an audit document to JSON.

.DESCRIPTION
Converts the ordered document to JSON text. Depth is set generously enough to
cover the nested handler and evidence structures, and compression is left off
so the output stays readable when written to a file by a human.

.PARAMETER Document
The document to serialize.

.PARAMETER Depth
Maximum object depth to serialize.
#>
function ConvertTo-AuditJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [object]$Document,

        [Parameter()]
        [int]$Depth = 12
    )

    return ($Document | ConvertTo-Json -Depth $Depth)
}
