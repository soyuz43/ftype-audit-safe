# src\core\ExitCode.ps1
# Defines the process exit codes the tool can return.
#
# The tool is documented as usable as a CI gate, but the exit code used to be
# 0 for every successful run - including runs that found unresolved issues.
# A CI job therefore had no way to fail on a broken association.
#
# The contract below separates "the tool ran successfully" from "the thing
# the tool audited is healthy". Consumers that only want to know whether the
# audit itself worked should check for 0; consumers that want to gate on
# association health should treat 4 as a finding, not as a tool failure.

# Exit codes returned by the script.
enum AuditExitCode {
    # The audit ran and the association is healthy.
    Success = 0

    # The audit ran, but the association has unresolved issues.
    # This is a finding, not a tool failure. A CI gate that wants to fail on
    # broken associations should treat this as a failure.
    IssuesFound = 4

    # The tool could not complete the requested operation.
    OperationFailed = 1

    # Registry access was denied.
    RegistryAccessFailure = 2

    # The input failed validation (malformed extension, empty path, and so on).
    ValidationFailure = 3

    # The environment is not supported (not Windows, or an unusable
    # PowerShell version).
    UnsupportedEnvironment = 5
}

<#
.SYNOPSIS
Maps an association diagnosis to the exit code that should be reported.

.DESCRIPTION
Returns AuditExitCode.IssuesFound when the diagnosis contains any evidence,
and AuditExitCode.Success when it does not. The operation-level failures are
handled separately by the caller, because they short-circuit the audit before
a diagnosis exists.

.PARAMETER Diagnosis
The AssociationDiagnosis to inspect. A null diagnosis is treated as healthy,
since it means nothing was found to examine.
#>
function Get-AuditExitCode {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()][AllowNull()]
        [object]$Diagnosis
    )

    if ($null -eq $Diagnosis) {
        return [int][AuditExitCode]::Success
    }

    if ($Diagnosis.Evidence.Count -gt 0) {
        return [int][AuditExitCode]::IssuesFound
    }

    return [int][AuditExitCode]::Success
}

<#
.SYNOPSIS
Returns the highest-severity exit code from a set of results.

.DESCRIPTION
Used by bulk mode, where each extension produces its own exit code. The
tool reports the most significant failure so a CI job fails if any single
extension is broken.

Operation failures (2, 3, 5) outrank findings (4), because a failed audit
means the association state is unknown, which is worse than a known problem.
The ordering is by numeric value except that 1 (OperationFailed) is treated
as more significant than 4 (IssuesFound).

.PARAMETER ExitCodes
The exit codes to combine.
#>
function Get-WorstExitCode {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()][AllowEmptyCollection()]
        [int[]]$ExitCodes = @()
    )

    if (-not $ExitCodes -or $ExitCodes.Count -eq 0) {
        return [int][AuditExitCode]::Success
    }

    $worst = [int][AuditExitCode]::Success
    foreach ($code in $ExitCodes) {
        # An operation failure outranks a finding.
        if ($code -eq [int][AuditExitCode]::OperationFailed) {
            return [int][AuditExitCode]::OperationFailed
        }
        if ($code -eq [int][AuditExitCode]::RegistryAccessFailure -or
            $code -eq [int][AuditExitCode]::ValidationFailure -or
            $code -eq [int][AuditExitCode]::UnsupportedEnvironment) {
            $worst = $code
        }
        elseif ($code -eq [int][AuditExitCode]::IssuesFound -and
                $worst -eq [int][AuditExitCode]::Success) {
            $worst = $code
        }
    }

    return $worst
}
