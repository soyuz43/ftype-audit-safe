# ftype-audit.ps1

<#
.SYNOPSIS
Analyzes and repairs Windows file association configurations safely.

.DESCRIPTION
Provides detailed inspection and safe modification capabilities for file type associations while maintaining registry integrity.

.PARAMETER Path
File path or extension to analyze (e.g. '.txt' or 'C:\file.json')

.PARAMETER Explain
Show technical interpretation of association states

.PARAMETER DryRun
Preview changes without modifying registry

.PARAMETER Clean
Perform safe cleanup of file association entries

.PARAMETER Backup
Create registry backup before making changes

.PARAMETER BackupPath
Custom location for registry backup (default: .\ftype-backup-*.reg)

.PARAMETER SkipConfirmation
Skip interactive confirmation prompts (Does NOT override critical safety logic)

.PARAMETER AllowBackupFailure
Continue the cleanup even when the registry backup failed. Off by default: a
failed backup aborts the cleanup unless this is explicitly requested.

.PARAMETER IsExtension
Treat input Path explicitly as an extension (bypass file-exists check)

.PARAMETER Literal
Display pure technical output without annotations

.PARAMETER Json
Emit a machine-readable JSON document instead of the human-readable report.
Written to stdout so it can be piped or redirected.

.PARAMETER OutputPath
Write the JSON document to this file instead of stdout.

.PARAMETER FailOnIssues
Exit with code 4 when the audit finds unresolved issues, so the tool can be
used as a CI gate. Off by default: the exit code still reports the finding,
but the run itself is not treated as a failure.

.PARAMETER Help
Show this help screen
#>
[CmdletBinding(DefaultParameterSetName = 'Analyze', SupportsShouldProcess = $true)]
param(
    # - Help only
    [Parameter(ParameterSetName = 'Help', HelpMessage = 'Show this help screen')]
    [switch]$Help,

    # - Path: used in both Analyze and Clean
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Analyze',
        HelpMessage = 'File path or extension to analyze')]
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Clean',
        HelpMessage = 'File path or extension to clean ghost handlers for')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    # - Analyze-only flags
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Show technical interpretation of association states')]
    [switch]$Explain,

    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Display pure technical output without annotations')]
    [switch]$Literal,

    # - Automation output
    #
    # These are available in the Clean parameter set as well, so a dry run
    # can be emitted as JSON too and compared against the real run.
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Emit machine-readable JSON output')]
    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Emit machine-readable JSON output')]
    [switch]$Json,

    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Write the JSON document to this file')]
    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Write the JSON document to this file')]
    [ValidateScript({
            $dir = Split-Path $_ -Parent
            if ($dir -and -not (Test-Path $dir)) {
                throw "Directory '$dir' does not exist."
            }
            $true
        })]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Exit non-zero when issues are found (CI gate)')]
    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Exit non-zero when issues are found (CI gate)')]
    [switch]$FailOnIssues,

    # - Clean-only flags
    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Preview changes without modifying registry')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Perform safe cleanup of file association entries')]
    [switch]$Clean,

    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Create registry backup before making changes')]
    [switch]$Backup,

    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Custom location for registry backup')]
    [ValidateScript({
            $dir = Split-Path $_
            if (-not (Test-Path $dir)) {
                throw "Directory '$dir' does not exist."
            }
            $true
        })]
    [string]$BackupPath = ".\ftype-backup-$(Get-Date -Format yyyyMMdd-HHmmss).reg",

    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Skip interactive confirmation prompts')]
    [switch]$SkipConfirmation,

    [Parameter(ParameterSetName = 'Clean', HelpMessage = 'Continue even when the registry backup fails (dangerous)')]
    [switch]$AllowBackupFailure,

    # - Shared flag (both sets)
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Treat Path explicitly as an extension')]
    [Parameter(ParameterSetName = 'Clean')]
    [switch]$IsExtension,

# - Python cleanup tools
    [Parameter(ParameterSetName = 'PythonAudit', HelpMessage = 'Run Python residue audit and exit')]
    [switch]$AuditPython

)
# Check if we are running in the dedicated Python Audit mode
if ($PSCmdlet.ParameterSetName -eq 'PythonAudit') {
    
    # Source the Python cleanup script
    . "$PSScriptRoot\cleanup\Python.ps1"

    # Execute Python audit functions
    # Example calls based on the provided Python.ps1 content:
    Test-PythonResiduals
    Get-PythonPathInfo
    Test-CommandExists -Command "python"
    Test-CommandExists -Command "pip"
    # Add other relevant audit functions from Python.ps1 as needed

    # Exit after running the audit
    exit 0
}

# ─────────────────────────────────────────────
# Utility helpers (safe to reuse anywhere)
# Load helpers
. "$PSScriptRoot\platform\PlatformContext.ps1"
. "$PSScriptRoot\core\Snapshot.ps1"
. "$PSScriptRoot\core\HandlerResolver.ps1"
. "$PSScriptRoot\core\MruList.ps1"
. "$PSScriptRoot\core\Diagnosis.ps1"
. "$PSScriptRoot\core\Reporter.ps1"
. "$PSScriptRoot\core\Repair.ps1"
. "$PSScriptRoot\core\RegistryHelpers.ps1"
. "$PSScriptRoot\core\ExitCode.ps1"
. "$PSScriptRoot\core\JsonOutput.ps1"
. "$PSScriptRoot\core\AuditRun.ps1"

# Skip validation in CI
if (-not (Test-CI)) {
    $context = Get-PlatformContext

    if (
        -not ( ($context.PowerShellEdition -eq 'Desktop' -and $context.PowerShellMajor -ge 5) -or
               ($context.PowerShellEdition -eq 'Core' -and $context.PowerShellMajor -ge 7) )
    ) {
        Write-Error "[X] Unsupported PowerShell edition/version."
        exit [int][AuditExitCode]::UnsupportedEnvironment
    }

    if (-not $context.IsWindows) {
        Write-Error "[X] Windows OS required."
        exit [int][AuditExitCode]::UnsupportedEnvironment
    }

    if (-not $context.IsElevated) {
        # In JSON mode stdout must contain nothing but the JSON document, so
        # the notice is redirected to stderr. Write-Warning writes to the
        # warning stream, which a consumer piping stdout never sees, but the
        # default host renders it into the captured stdout - which would
        # make the JSON unparseable.
        if ($Json) {
            [Console]::Error.WriteLine("[!] Process is not elevated - HKLM writes will be disabled.")
        }
        else {
            Write-Warning "[!] Process is not elevated - HKLM writes will be disabled."
        }
    }
}


# ── Show help and exit immediately ─────────────────────────────────────────────
if ($Help) {

    $helpText = @'
[🔒] Safe File Association Analyzer

USAGE:
  ftype-audit.ps1 -Path <.ext | file> [options]

CORE ACTIONS:
  -Clean              Perform safe cleanup of file association entries
  -DryRun             Preview cleanup actions without modifying registry
  -Backup             Create a registry backup before changes
  -BackupPath         Custom location for registry backup (default: .\ftype-backup-*.reg)

INPUT INTERPRETATION:
  -IsExtension        Treat input Path as a file extension (e.g. "txt" → ".txt")

OUTPUT MODES:
  -Explain            Human-readable interpretation of file association state
  -Literal            Pure technical dump of registry and MRU values

AUTOMATION:
  -Json               Emit a machine-readable JSON document on stdout
  -OutputPath         Write the JSON document to a file instead of stdout
  -FailOnIssues       Exit with code 4 when the audit finds unresolved issues
                      [!] Off by default: an audit that finds issues still
                          exits 0, because the tool did its job. Use this to
                          turn the tool into a CI gate.

EXIT CODES:
  0  Audit completed, no issues found
  1  The requested operation could not be completed
  2  Registry access was denied
  3  The input failed validation
  4  Issues were found (only with -FailOnIssues)
  5  Unsupported environment

EXECUTION CONTROL:
  -SkipConfirmation   Suppress confirmation prompts (ShouldContinue)
                      [!] Only affects -Clean or -DryRun
                      [!] Does NOT disable backup protection
  -AllowBackupFailure Proceed even when the registry backup fails
                      [!] Dangerous - the association may be unrestorable

HELP:
  -Help               Show this help screen

EXAMPLES:
  .\ftype-audit.ps1 -Path .json -DryRun -Backup
      [>] Show what would be removed from MRU with backup

  .\ftype-audit.ps1 -Path .txt -Clean -SkipConfirmation
      [>] Clean ghost MRU handlers for .txt without prompt

  .\ftype-audit.ps1 -Path .ps1 -Explain
      [>] Explain .ps1 association state semantically

  .\ftype-audit.ps1 -Path .pdf -Literal
      [>] Dump raw registry data related to .pdf association

  .\ftype-audit.ps1 -Path .txt,.pdf -Json
      [>] Audit several extensions and emit JSON

  .\ftype-audit.ps1 -Path .txt -FailOnIssues
      [>] Exit non-zero when .txt has unresolved issues (CI gate)

Learn more:
  https://github.com/soyuz43/ftype-audit-safe
'@

    # Emit to the Information stream so the text is visible-by-default
    # yet suppressible with -InformationAction SilentlyContinue or
    # $InformationPreference = 'SilentlyContinue'.
    Write-Information $helpText -InformationAction Continue

    # ▸ you now have `$helpText` in memory if you later want to log it:
    #   $helpText | Out-File -FilePath .\help.txt -Encoding UTF8
    exit 0
}
#region -- Execution Flow ----------------------------------------------------
<#
.SYNOPSIS
Validates a file-path or extension, captures the current association state,
reports health, and (optionally) performs a safe cleanup.

EXIT CODES
0  Success
1  User cancellation / bad interactive input
2  Permission denied
3  Validation failure
#>

#-- Helper: validate path / extension ------------------------
function Get-ValidatedExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RawInput
    )

    $raw = $RawInput.Trim('"''')
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw '[ERR-EXT-01] Empty input'
    }

    # Path branch --------------------------------------------
    if (Test-Path -LiteralPath $raw) {
        $item = Get-Item -LiteralPath $raw -Force
        if ($item.PSIsContainer) { throw "[ERR-EXT-02] Directory provided: '$raw'" }
        if (-not $item.Extension) { throw "[ERR-EXT-03] File has no extension: '$raw'" }
        return $item.Extension.ToLowerInvariant()
    }

    # Extension branch ---------------------------------------
    $ext = if ($raw.StartsWith('.')) { $raw } else { ".$raw" }
    if ($ext -notmatch '^\.[A-Za-z0-9](?:[\w-]{0,254})$') {
        throw "[ERR-EXT-04] Invalid extension format: '$ext'"
    }
    return $ext.ToLowerInvariant()
}

#-- Interactive prompt only if -Path truly missing -----------
if (-not $PSBoundParameters.ContainsKey('Path')) {
    if ([Environment]::UserInteractive -and ($Host.Name -ne 'Default Host')) {
        $Path = Read-Host 'Enter target file or extension'
        if ([string]::IsNullOrWhiteSpace($Path)) {
            Write-Error '[X] No input provided'; exit 1
        }
    } else {
        Write-Error '[X] Non-interactive session: -Path required'; exit 1
    }
}

#-- Validation ------------------------------------------------
# The path may name a single extension or a comma-separated list. Invalid
# entries are reported and skipped rather than aborting the whole run - a
# typo in one entry of a bulk list should not hide the state of the others.
$resolved = Resolve-ExtensionList -Inputs @($Path) -Resolver { param($x) Get-ValidatedExtension $x }

if ($resolved.Errors.Count -gt 0) {
    foreach ($err in $resolved.Errors) {
        if ($Json) {
            # stdout must stay parseable JSON, so notices go to stderr.
            [Console]::Error.WriteLine("[!] Skipping invalid input '$($err.input)': $($err.message)")
        }
        else {
            Write-Warning "[!] Skipping invalid input '$($err.input)': $($err.message)"
        }
    }
}

if ($resolved.Extensions.Count -eq 0) {
    Write-Error '[X] Validation failure: no valid extension could be resolved from the supplied path.'
    exit [int][AuditExitCode]::ValidationFailure
}

$resolvedExts = @($resolved.Extensions)

if ($SkipConfirmation -and -not ($Clean -or $DryRun)) {
    Write-Warning '[!] -SkipConfirmation ignored without -Clean or -DryRun'
}

#-- Audit ----------------------------------------------------
$auditRun = Invoke-AuditRun -Extensions $resolvedExts

#-- Presentation ---------------------------------------------
# In JSON mode the human-readable report is suppressed, so that stdout
# contains nothing but the JSON document and stays parseable.
if (-not $Json) {
    $mode = if ($Literal) { 'Literal' } elseif ($Explain) { 'Explain' } else { 'Summary' }
    foreach ($audit in $auditRun.Results) {
        Write-AssociationReport -Snapshot $audit.Snapshot -Diagnosis $audit.Diagnosis -Mode $mode
    }
}

#-- Remediation (DryRun / Clean) -----------------------------
$jsonDocuments = @()
$exitCode = $auditRun.ExitCode

foreach ($audit in $auditRun.Results) {
    $resolvedExt  = $audit.Extension
    $snapshot     = $audit.Snapshot
    $diagnosis    = $audit.Diagnosis
    $document     = $null

    if ($Json) {
        $document = New-AuditJsonDocument -Snapshot $snapshot `
                                           -Diagnosis $diagnosis `
                                           -Resolutions $audit.Resolutions
    }

    if ($Clean -or $DryRun) {

        $needPrompt = -not $SkipConfirmation -and -not $DryRun
        if ($needPrompt) {
            $choice = $Host.UI.PromptForChoice(
                'Confirm Action',
                "Modify system associations for $resolvedExt?",
                @(
                    [System.Management.Automation.Host.ChoiceDescription]::new('&Proceed','Execute changes'),
                    [System.Management.Automation.Host.ChoiceDescription]::new('&Cancel','Abort')
                ),
                0   # default = Proceed
            )
            if ($choice -ne 0) {
                Write-Information '[>] Operation cancelled.' -InformationAction Continue
                exit 0
            }
        }

        if ($PSCmdlet.ShouldProcess($resolvedExt, 'Repair registry association')) {
            try {
                # Parameter mapping:
                # - $snapshot         -> -Map
                # - $diagnosis        -> -Diagnosis
                # - $Backup           -> -Backup
                # - $BackupPath       -> -BackupPath
                # - $DryRun           -> -DryRun
                # - $SkipConfirmation -> -Force (to bypass the internal ShouldContinue prompt)
                #
                # The dry run used to be handled here by printing the diagnosis
                # evidence, which duplicated what Invoke-SafeClean already does -
                # and did it less completely, since it never showed the MRUList
                # rewrite. Delegating keeps the preview and the real run in step.
                #
                # -BackupPath also used to be dropped here, so a caller-supplied
                # path was silently ignored and the backup landed in the default
                # location instead.
                Invoke-SafeClean -Map $snapshot `
                                 -Diagnosis $diagnosis `
                                 -Backup:$Backup `
                                 -BackupPath $BackupPath `
                                 -DryRun:$DryRun `
                                 -Quiet:$Json `
                                 -Force:$SkipConfirmation `
                                 -AllowBackupFailure:$AllowBackupFailure
            } catch {
                Write-Error "[X] Repair failed: $($_.Exception.Message)" -Category OperationStopped
                exit [int][AuditExitCode]::OperationFailed
            }
        }

        # Record what the repair did (or would have done) for the JSON
        # document. The plan is computed from the diagnosis, which is the
        # same source the repair itself uses.
        if ($Json) {
            $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$resolvedExt\OpenWithList"
            $currentMru   = Get-MruListForRepair -Map $snapshot -OpenWithPath $openWithPath
            $plannedMru   = Get-CorrectedMruList -CurrentMruList $currentMru `
                                                -RemovedKeys @($diagnosis.BrokenHandlerKeys)
            $null = Add-RepairPlanToJsonDocument -Document $document `
                                                 -PlannedRemovals @($diagnosis.BrokenHandlerKeys) `
                                                 -CurrentMruList $currentMru `
                                                 -PlannedMruList $plannedMru `
                                                 -Applied:(-not $DryRun)
        }
    }

    if ($document) {
        $jsonDocuments += $document
    }
}

#-- Exit code decision ---------------------------------------
# The audit outcome and the process exit code are deliberately separate.
#
# The audit outcome says what was found: 0 for a healthy association, 4 for
# one with unresolved issues, and a failure code when the audit could not
# be completed at all.
#
# The process exit code says whether the *run* should be treated as a
# failure. By default an audit that found issues still exits 0, because the
# tool did its job successfully and the findings are in the output. With
# -FailOnIssues the finding is promoted to a failure, which is what a CI
# gate wants.
#
# A failure to complete the audit always exits non-zero, regardless of the
# switch, because in that case the state of the association is unknown -
# which is worse than a known problem.
$processExitCode = $exitCode
if (-not $FailOnIssues -and $exitCode -eq [int][AuditExitCode]::IssuesFound) {
    $processExitCode = [int][AuditExitCode]::Success
}

#-- JSON output ----------------------------------------------
if ($Json) {
    $outputDocument = [ordered]@{
        schemaVersion = (Get-JsonSchemaVersion)
        generatedAt   = (Get-Date).ToString('o')
        mode          = $(if ($Clean) { 'clean' } elseif ($DryRun) { 'dryRun' } else { 'analyze' })
        extensions    = @($jsonDocuments)
        failures      = @($auditRun.Failures)
        # Inputs that could not be validated. These are reported rather than
        # aborting the run, so a bulk list with a typo still audits the rest.
        invalidInputs = @($resolved.Errors)
        # exitCode is the audit outcome; processExitCode is what this process
        # will return. They differ only when -FailOnIssues was not supplied
        # and issues were found.
        exitCode      = $exitCode
        processExitCode = $processExitCode
    }

    $jsonText = ConvertTo-AuditJson -Document $outputDocument

    if ($OutputPath) {
        $outFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $jsonText | Set-Content -LiteralPath $outFile -Encoding UTF8
        Write-Verbose "[>] JSON written to '$outFile'."
    }
    else {
        # Written to stdout via the success stream so it can be piped.
        # Write-Output would be right too, but Write-Host is avoided here
        # because it bypasses the pipeline entirely.
        Write-Output $jsonText
    }
}

exit $processExitCode


