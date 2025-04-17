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

    # - Shared flag (both sets)
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Treat Path explicitly as an extension')]
    [Parameter(ParameterSetName = 'Clean')]
    [switch]$IsExtension,

    # - Python cleanup tools
    [Parameter(HelpMessage = 'Run Python residue audit and exit')]
    [switch]$AuditPython

)

if ($AuditPython -and $PSCmdlet.ParameterSetName -ne '') {
    Write-Error "The -AuditPython flag cannot be used with other operation modes."
    exit 1
}

#end region

#region Environment Validation & Bootstrap

# Exit codes for clarity in pipelines
enum ExitCode {
    Success = 0
    UnsupportedEnvironment = 1
    RegistryAccessFailure = 2
    InsufficientElevation = 3
}

# 1. PowerShell edition & version
$psMajor = $PSVersionTable.PSVersion.Major
$edition = $PSVersionTable.PSEdition   # ← safe local name
if (
    -not ( ($edition -eq 'Desktop' -and $psMajor -ge 5) -or
            ($edition -eq 'Core' -and $psMajor -ge 7) )
)
{
    Write-Error "[X] Unsupported PowerShell edition/version. Requires Desktop 5.1+ or Core 7.0+ on Windows."
    exit [int][ExitCode]::UnsupportedEnvironment}

# 2. OS platform
if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Error "[X] Windows OS required for registry operations."
    exit [int][ExitCode]::UnsupportedEnvironment}

# 3. Registry provider & drive presence
try {
    Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
}
catch {
    Write-Error "[X] Failed to load Registry provider: $($_.Exception.Message)"
    exit [int][ExitCode]::RegistryAccessFailure
}

if (-not (Test-Path HKLM:\) -or -not (Test-Path HKCU:\)) {
    Write-Error "[X] Registry drives HKLM: or HKCU: are unavailable."
    exit [int][ExitCode]::InsufficientElevation
}

# 4. Deep registry read probe (32/64-bit aware)
$hives = @(
    @{ Hive = 'LocalMachine'; PSPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; SubKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' },
    @{ Hive = 'CurrentUser'; PSPath = 'HKCU:\Volatile Environment'; SubKey = 'Volatile Environment' }
)
$errors = @()
foreach ($h in $hives) {
    try {
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            $base = [Microsoft.Win32.RegistryHive]::$($h.Hive)
            [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                $base,
                [Microsoft.Win32.RegistryView]::Registry64
            ).OpenSubKey($h.SubKey) | Out-Null
        }
        else {
            Get-Item -Path $h.PSPath -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $errors += "• Cannot read $($h.PSPath): $($_.Exception.Message)"
    }
}
if ($errors.Count) {
    Write-Error "[!] Registry access validation failed:`n$($errors -join "`n")"
    exit [int][ExitCode]::InsufficientElevation
}
#endregion

#region Python Residue Tools
if ($AuditPython) {
    . "$PSScriptRoot\src\Cleanup-PythonResidue.ps1"

    Test-PythonResiduals
    Get-PythonPathInfo
    Test-CommandExists -Command 'python'
    Test-CommandExists -Command 'pip'

    return [int][ExitCode]::Success
}
#endregion


#region Elevation Check

Add-Type -MemberDefinition @'
    using System;
    using System.Runtime.InteropServices;
    public class TokenHelper {
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInfoClass, out int TokenInfo, int TokenInfoLength, out int ReturnLength);
    }
'@ -Name 'TokenHelper' -Namespace 'Win32' -ErrorAction SilentlyContinue

function Test-IsElevated {
    $procHandle = [System.Diagnostics.Process]::GetCurrentProcess().Handle
    $tokenHandle = [IntPtr]::Zero
    [Win32.TokenHelper]::OpenProcessToken($procHandle, 0x8, [ref]$tokenHandle) | Out-Null
    $info = 0; $size = 0
    [Win32.TokenHelper]::GetTokenInformation($tokenHandle, 20, [ref]$info, 4, [ref]$size) | Out-Null
    return ($info -eq 2)  # 2 = Full elevation
}

if (-not (Test-IsElevated)) {
    Write-Warning "[!] Process is not elevated-HKLM writes will be disabled."
}

#endregion

#region Data Collection

function Get-AssociationSnapshot {
    param(
        [Parameter(Mandatory)][ValidatePattern('^\.[a-z0-9]{1,10}$')]
        [string]$Extension
    )

    $snapshot = [AssociationSnapshot]::new()
    $snapshot.Extension = $Extension.ToLower()

    # Capture raw registry state
    try {
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        if (Test-Path $userChoicePath) {
            $snapshot.RegistryValues.UserChoice = Get-ItemProperty $userChoicePath
        }
    }
    catch { /* Log access issues */ }

    try {
        $snapshot.RegistryValues.SystemDefault = (Get-ItemProperty "HKCR:\$Extension" -ErrorAction Stop).'(default)'
    }
    catch { /* Log missing key */ }

    try {
        $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithList"
        if (Test-Path $openWithPath) {
            $snapshot.RegistryValues.OpenWithList = Get-ItemProperty $openWithPath
        }
    }
    catch { /* Log access issues */ }

    return $snapshot
}
#endregion

#region Analysis Engine
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
#endregion

#region Reporting

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
            Write-Information ("User Choice:    {0}" -f ($Snapshot.RegistryValues.UserChoice?.ProgId ?? '<not set>')) -InformationAction Continue
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
        }
    }
}

#endregion



#endregion


function Backup-RegistryState {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$ext
    )

    $backupCommand = "reg export `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext`" `"$BackupPath`" /y"
    try {
        Invoke-Expression $backupCommand -ErrorAction Stop
        Write-Host "Backup created: $BackupPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Backup failed: $_" -ForegroundColor Red
        return $false
    }
}

function Invoke-SafeClean {
    <#
        .SYNOPSIS
            Cleans ghost file-association handlers for a given extension.

        .DESCRIPTION
            Removes non-existent ProgID entries from the current user's OpenWithList.
            Supports dry-run preview, optional registry backup, forceful execution in
            non-interactive contexts, and verbose instrumentation.

        .PARAMETER Map
            An [AssociationSnapshot] object describing the extension and its handlers.

        .PARAMETER Force
            Bypasses interactive confirmation and continues despite backup failures.

        .PARAMETER DryRun
            Shows the planned Remove-ItemProperty commands without executing them.

        .PARAMETER Backup
            Creates a backup of the relevant registry branch before modification.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Map,

        [switch]$Force,
        [switch]$DryRun,
        [switch]$Backup
    )

    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Map.Extension)\OpenWithList"

    # Identify handlers whose executable path no longer exists
    $ghosts = $Map.Handlers.GetEnumerator() | Where-Object { -not $_.Value.Exists }

    # ── Dry-Run Preview ─────────────────────────────────────────────────────────
    if ($DryRun) {
        Write-Information "[>] Planned operations for extension '$($Map.Extension)'" -InformationAction Continue
        $ghosts | ForEach-Object {
            Write-Information "    Remove-ItemProperty -Path $openWithPath -Name $($_.Key)" -InformationAction Continue
        }
        return
    }

    # ── ShouldProcess Gate ──────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess($Map.Extension, 'Modify registry associations')) {
        return
    }

    # ── Interactive Confirmation ───────────────────────────────────────────────
    if (-not $Force) {
        $proceed = $PSCmdlet.ShouldContinue(
            "Proceed with cleaning ghost handlers for extension '$($Map.Extension)'?",
            'Confirm Cleanup'
        )
        if (-not $proceed) {
            Write-Information "[>] Cleanup skipped by user" -InformationAction Continue
            return
        }
    }

    # ── Optional Registry Backup ───────────────────────────────────────────────
    if ($Backup) {
        try {
            Backup-RegistryState $Map.Extension -ErrorAction Stop | Out-Null
            Write-Verbose "[>] Registry backup completed."
        }
        catch {
            $msg = "[!] Backup failed: $($_.Exception.Message)"
            if ($Force) {
                Write-Warning $msg
            }
            else {
                Write-Error "[X] $msg. Aborting."; return
            }
        }
    }

    # ── Perform Cleanup ─────────────────────────────────────────────────────────
    foreach ($handler in $ghosts) {
        try {
            Remove-ItemProperty -Path $openWithPath -Name $handler.Key -ErrorAction Stop
            Write-Verbose "[>] Removed handler '$($handler.Key)'"
        }
        catch {
            Write-Warning "[!] Failed to remove handler '$($handler.Key)': $($_.Exception.Message)"
        }
    }
}
#endregion




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
        if ($DryRun) {
            Write-Information '[>] Simulated repair operations:' -InformationAction Continue
            $diagnosis.Evidence | ForEach-Object {
                Write-Information "    would fix: $_" -InformationAction Continue
            }
        } else {
            try {
                Repair-Association -Snapshot $snapshot -Diagnosis $diagnosis `
                                   -Backup:$Backup -BackupPath $BackupPath
            } catch {
                Write-Error "[X] Repair failed: $($_.Exception.Message)" -Category OperationStopped
                exit 1
            }
        }
    }
}
#endregion




# SIG # Begin signature block
# MIIFgwYJKoZIhvcNAQcCoIIFdDCCBXACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDUalIbUPRwYGy5
# oN7U/kC8BRDfX//FVB0yHu7Vs5jofaCCAv4wggL6MIIB4qADAgECAhAgUkHtEQTC
# q0UgHK9KUqndMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMMCkZ0eXBlQXVkaXQw
# HhcNMjUwNDE2MTg0ODEyWhcNMjYwNDE2MTkwODEyWjAVMRMwEQYDVQQDDApGdHlw
# ZUF1ZGl0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyeTXgrocB8ed
# zZFAi/ABqtdbI8JZs/uxYBInLmpLAtyo26jSw1bNSKRKVx8gYP7FsHydyzqi57v7
# o57Jgy75rbT54NfthbLEn9BrACpG2psABeSfLJWjfFsLOS1anS+JX+cCv61ZHWMy
# GSEQEfDKyABrbnvKnbrKCkbtZ2cdiGhcIEGe8PzM3JIiCchbY2qVB0NKXxLVpaPe
# 0UfTuL2aHMMuORlioCu1o+1vgxy/73q+HPXMTzjIe0qrmVerW4l1D4uVmj4KBvav
# F+BFReVmcnLXAA2d5HcZLcuSoi1jKZhVvV/TDScQKf2mt8f8sIZ2TLirqe0ft+je
# PziAnEkeSQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFPE86AvlpnOBJJEuRFZo5jLZWojqMA0GCSqGSIb3DQEB
# CwUAA4IBAQCHOUJbQj8x6aF0HKRCKg7+tXI1ZeR1Bw4CYKSpSITKoVMn2+8ih7RT
# UMkc9ehTIwW1dOK17Bcq+q4A1UpIfr6dSUVqjoRX4jRtoUD5tHK4c2gcznafZIhR
# 75C5pLSKXguaxKKrU9qmwwj+HTToqkD4mHvLyLjcLwn9xtHwk3WhJsdR/tmE0C6d
# ovHfahVTGCrL0O6Y8CQUqeblQKABf3dvt9IwSXkHYNk4xLMBiQEgw5o/Z3iZxIE2
# n+g8j+8aoXOsEQ7ckIekPJUxn6rqs75GCR7XjIE1p5XfePQR7PwOwKbNPoNXmyJ8
# U7ymxIQZEc+0EH+XHhDI6rJQvHVLz+NoMYIB2zCCAdcCAQEwKTAVMRMwEQYDVQQD
# DApGdHlwZUF1ZGl0AhAgUkHtEQTCq0UgHK9KUqndMA0GCWCGSAFlAwQCAQUAoIGE
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIFpP8NkOAHAy/RDmm6P7UNX+uoSGYO4i6fcECFCfgKCYMA0GCSqGSIb3DQEB
# AQUABIIBALeasSMWAmzyZ+eMI76Br9EKmV0URmq8ktoOGM1UR7cdUf/DJIFLeysg
# xrF+5dA6pkCUIxCDPcyyFelLfzYDqWFT6RRJJi0xsqtOKdvyVAGkVCXsRg6d7ZKF
# GCcip4vmKXG5X85xIDBVAoCwsZ9vE0WlNhUn3ZmPAFV0XoNXolSOLYiRvzaI8T4p
# jMLIuGPwpC0LIbu0MnTWBlrM6pA4I4tgP5WKcDMGLyXGpEQzkvFDv2RuaLQXyZvQ
# iBQ9TqTR6Mcp7A60YJ1zpRj00j225l5Zs+QWn2cnHfD0bUfcMlzFD3gULLq2a0P0
# /q/ebj8g24zZS8lAgIOkQMTqhJFlRVI=
# SIG # End signature block

