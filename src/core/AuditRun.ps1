# src\core\AuditRun.ps1
# Runs the audit across one or more extensions and produces a result set.
#
# The script front end used to handle exactly one extension per invocation.
# Auditing a set of extensions therefore meant running the script in a loop
# from the outside, and parsing prose output to find out what happened.
#
# This module moves the per-extension work into a function that can process
# many extensions in one pass, and returns structured results. The script
# uses it for both the single-extension and the bulk case, so the two paths
# cannot drift apart.

<#
.SYNOPSIS
Validates and normalizes a list of extension inputs.

.DESCRIPTION
Accepts a single extension, a comma-separated list, or an array, and returns
the normalized, de-duplicated extension list. Entries that cannot be
validated are reported rather than silently dropped, because a typo in a
bulk list should not quietly shrink the scope of an audit.

.PARAMETER Inputs
The raw input strings.

.PARAMETER Resolver
The script-level extension resolver function to call. Passed in rather than
dot-sourced so this module stays independent of the front end.

.OUTPUTS
A hashtable with 'Extensions' (the valid ones) and 'Errors' (the invalid
ones, with their messages).
#>
function Resolve-ExtensionList {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]
        [object[]]$Inputs,

        [Parameter(Mandatory)]
        [scriptblock]$Resolver
    )

    $extensions = @()
    $errors = @()

    foreach ($raw in @($Inputs)) {
        if ([string]::IsNullOrWhiteSpace([string]$raw)) {
            continue
        }

        # Split comma-separated values, so -Path '.txt,.pdf' works.
        foreach ($piece in ([string]$raw -split ',')) {
            $candidate = $piece.Trim()
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                continue
            }

            try {
                $resolved = & $Resolver $candidate
                if ($resolved -and ($extensions -notcontains $resolved)) {
                    $extensions += $resolved
                }
            }
            catch {
                $errors += [ordered]@{
                    input   = $candidate
                    message = $_.Exception.Message
                }
            }
        }
    }

    return @{
        Extensions = $extensions
        Errors     = $errors
    }
}

<#
.SYNOPSIS
Audits one extension and returns a structured result.

.DESCRIPTION
Captures the snapshot, runs the health check, and resolves the handlers. The
result carries everything the JSON emitter and the exit-code logic need,
without performing any registry mutation.

.PARAMETER Extension
The already-validated extension.

.OUTPUTS
A hashtable describing the audit outcome for this extension.
#>
function Invoke-AssociationAudit {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$Extension
    )

    $snapshot = Get-AssociationSnapshot -Extension $Extension
    $diagnosis = Test-AssociationHealth -Snapshot $snapshot

    # Resolve the handlers a second time for reporting detail. The health
    # check already resolved them internally, but does not expose the
    # per-handler outcome, and the JSON document needs that detail.
    $resolutions = $null
    try {
        $resolutions = Resolve-OpenWithListHandlers -Snapshot $snapshot
    }
    catch {
        # Reporting detail is best-effort. A failure here must not lose the
        # audit result itself.
        $resolutions = $null
    }

    return @{
        Extension   = $Extension
        Snapshot    = $snapshot
        Diagnosis   = $diagnosis
        Resolutions = $resolutions
        ExitCode    = (Get-AuditExitCode -Diagnosis $diagnosis)
    }
}

<#
.SYNOPSIS
Audits a list of extensions and returns a result set.

.DESCRIPTION
Runs Invoke-AssociationAudit for each extension. A failure on one extension
does not abort the run: the remaining extensions are still audited and the
failing one is recorded with its error. This matches how a CI audit should
behave - one broken extension should not hide the state of the others.

.PARAMETER Extensions
The validated extension list.

.OUTPUTS
A hashtable with 'Results' (successful audits), 'Failures' (extensions that
could not be audited), and 'ExitCode' (the combined exit code).
#>
function Invoke-AuditRun {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]
        [string[]]$Extensions = @()
    )

    $results = @()
    $failures = @()
    $codes = @()

    foreach ($extension in $Extensions) {
        try {
            $audit = Invoke-AssociationAudit -Extension $extension
            $results += $audit
            $codes += $audit.ExitCode
        }
        catch {
            $failures += [ordered]@{
                extension = $extension
                message   = $_.Exception.Message
            }
            # A failed audit means the state is unknown, which is reported as
            # an operation failure rather than a finding.
            $codes += [int][AuditExitCode]::OperationFailed
        }
    }

    return @{
        Results   = $results
        Failures  = $failures
        ExitCode  = (Get-WorstExitCode -ExitCodes $codes)
    }
}
