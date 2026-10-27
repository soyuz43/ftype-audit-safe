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

# Skip validation in CI
if (-not (Test-CI)) {
    $context = Get-PlatformContext

    if (
        -not ( ($context.PowerShellEdition -eq 'Desktop' -and $context.PowerShellMajor -ge 5) -or
               ($context.PowerShellEdition -eq 'Core' -and $context.PowerShellMajor -ge 7) )
    ) {
        Write-Error "[X] Unsupported PowerShell edition/version."
        exit [int][ExitCode]::UnsupportedEnvironment
    }

    if (-not $context.IsWindows) {
        Write-Error "[X] Windows OS required."
        exit [int][ExitCode]::UnsupportedEnvironment
    }

    if (-not $context.IsElevated) {
        Write-Warning "[!] Process is not elevated — HKLM writes will be disabled."
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

#-- Validation + snapshot ------------------------------------
try {
    $resolvedExt = Get-ValidatedExtension $Path
    $snapshot    = Get-AssociationSnapshot -Extension $resolvedExt
} catch [System.Security.SecurityException] {
    Write-Error "[X] Permission denied: $($_.Exception.Message)" -Category PermissionDenied
    exit 2
} catch {
    Write-Error "[X] Validation failure: $($_.Exception.Message)"
    exit 3
}

#-- Diagnosis ------------------------------------------------
$diagnosis = Test-AssociationHealth -Snapshot $snapshot

if ($SkipConfirmation -and -not ($Clean -or $DryRun)) {
    Write-Warning '[!] -SkipConfirmation ignored without -Clean or -DryRun'
}

#-- Presentation ---------------------------------------------
$mode = if ($Literal) { 'Literal' } elseif ($Explain) { 'Explain' } else { 'Summary' }
Write-AssociationReport -Snapshot $snapshot -Diagnosis $diagnosis -Mode $mode

#-- Remediation (DryRun / Clean) -----------------------------
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
        if ($choice -ne 0) { Write-Information '[>] Operation cancelled.' -InformationAction Continue; exit 0 }
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
                             -Force:$SkipConfirmation `
                             -AllowBackupFailure:$AllowBackupFailure
        } catch {
            Write-Error "[X] Repair failed: $($_.Exception.Message)" -Category OperationStopped
            exit 1
        }
    }
}


