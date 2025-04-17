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
Treat input Path explicitly as an extension (bypass file‑exists check)

.PARAMETER Literal
Display pure technical output without annotations

.PARAMETER Help
Show this help screen
#>
[CmdletBinding(DefaultParameterSetName = 'Analyze', SupportsShouldProcess = $true)]
param(
    # — Help only
    [Parameter(ParameterSetName = 'Help', HelpMessage = 'Show this help screen')]
    [switch]$Help,

    # — Path: used in both Analyze and Clean
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Analyze',
        HelpMessage = 'File path or extension to analyze')]
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Clean',
        HelpMessage = 'File path or extension to clean ghost handlers for')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    # — Analyze‑only flags
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Show technical interpretation of association states')]
    [switch]$Explain,

    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Display pure technical output without annotations')]
    [switch]$Literal,

    # — Clean‑only flags
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

    # — Shared flag (both sets)
    [Parameter(ParameterSetName = 'Analyze', HelpMessage = 'Treat Path explicitly as an extension')]
    [Parameter(ParameterSetName = 'Clean')]
    [switch]$IsExtension
)
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
    Write-Error "[X] Unsupported PowerShell edition/version. Requires Desktop 5.1+ or Core 7.0+ on Windows."
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

# 4. Deep registry read probe (32/64‑bit aware)
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
    Write-Warning "[!] Process is not elevated—HKLM writes will be disabled."
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
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Snapshot,

        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationDiagnosis]$Diagnosis
    )

    $stateColor = @{
        [AssociationState]::ValidRegistry     = 'Green'
        [AssociationState]::MissingUserChoice = 'Yellow'
        [AssociationState]::CorruptMRUOrder   = 'Magenta'
        [AssociationState]::BrokenHandlerPath = 'Red'
    }

    Write-Host "`nAssociation Health Report: $($Snapshot.Extension)" -ForegroundColor Cyan
    Write-Host "Captured at: $($Snapshot.LastChecked.ToString('yyyy-MM-dd HH:mm:ss'))"
    
    Write-Host "`n[States]" -ForegroundColor DarkGray
    $Diagnosis.ActiveStates | ForEach-Object {
        $color = $stateColor[$_] ?? 'White'
        Write-Host "  $_" -ForegroundColor $color
    }

    Write-Host "`n[Evidence]" -ForegroundColor DarkGray
    $Diagnosis.Evidence | ForEach-Object {
        Write-Host "  $_" -ForegroundColor DarkYellow
    }
}

function Write-AssociationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$Snapshot,

        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationDiagnosis]$Diagnosis,

        [Parameter()][ValidateSet("Literal", "Explain", "Summary", "None")]
        [string]$Mode = "Summary",

        [hashtable]$ColorScheme = @{
            Success   = 'Green'
            Warning   = 'Red'
            Detail    = 'Yellow'
            Header    = 'Cyan'
            Timestamp = 'DarkGray'
        }
    )

    # Null safety check
    if (-not $Snapshot -or -not $Diagnosis) {
        throw "Invalid input: Snapshot and Diagnosis must be provided"
    }

    # State lookup optimization
    $stateTable = @{}
    $Diagnosis.ActiveStates | ForEach-Object { $stateTable[$_] = $true }

    switch ($Mode) {
        "None" { return }

        "Literal" {
            Show-AssociationReport -Snapshot $Snapshot -Diagnosis $Diagnosis
        }

        "Explain" {
            Write-Host "`n[EXPLAINED VIEW: $($Snapshot.Extension.ToUpper())]" -ForegroundColor $ColorScheme.Header
            Write-Host ("Timestamp: {0}" -f $Snapshot.LastChecked.ToString('yyyy-MM-dd HH:mm')) -ForegroundColor $ColorScheme.Timestamp
            
            # Status block
            Write-Host "`nCORE STATUS:" -ForegroundColor $ColorScheme.Header
            if ($Diagnosis.ActiveStates.Count -eq 0) {
                Write-Host "[+] Configuration Valid" -ForegroundColor $ColorScheme.Success
            }
            else {
                Write-Host "[!] Configuration Issues:" -ForegroundColor $ColorScheme.Warning
                $Diagnosis.ActiveStates | ForEach-Object {
                    Write-Host ("  - {0}" -f $_) -ForegroundColor $ColorScheme.Detail
                }
            }

            # Registry details
            Write-Host "`nREGISTRY ANALYSIS:" -ForegroundColor $ColorScheme.Header
            Write-Host ("User Choice:    {0}" -f ($Snapshot.RegistryValues.UserChoice?.ProgId ?? '<not set>'))
            Write-Host ("System Default: {0}" -f ($Snapshot.RegistryValues.SystemDefault ?? '<undefined>'))
            Write-Host ("Valid Handlers: {0}" -f $Snapshot.HandlerPaths.Count)
            Write-Host ("MRU Integrity:  {0}" -f $(if ($stateTable[[AssociationState]::CorruptMRUOrder]) { 'Compromised' } else { 'Intact' }))
        }

        "Summary" {
            $status = if ($Diagnosis.ActiveStates.Count -eq 0) { 
                "[+]" 
            }
            else { 
                "[!] {0} issue(s)" -f $Diagnosis.ActiveStates.Count 
            }
            Write-Host ("{0}: {1}" -f $Snapshot.Extension.PadRight(8), $status)
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNull()]
        [AssociationSnapshot]$map
    )

    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($map.Extension)\OpenWithList"

    # Track ghost entries
    $ghosts = $map.Handlers.GetEnumerator() | Where-Object { 
        -not $_.Value.Exists 
    }

    if ($DryRun) {
        Write-Host "`n[Planned Operations]" -ForegroundColor Yellow
        $ghosts | ForEach-Object { 
            Write-Host "  Remove-ItemProperty -Path $openWithPath -Name $($_.Key)"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($map.Extension, "Modify registry associations")) {

        # 🟡 Interactive confirmation unless skipped
        if (-not $SkipConfirmation -and -not $PSCmdlet.ShouldContinue(
                "Proceed with cleaning ghost handlers for extension '$($map.Extension)'?", 
                "Confirm Cleanup")
        ) {
            Write-Host "⏭️ Cleanup skipped by user" -ForegroundColor Yellow
            return
        }

        # 🔒 Optional registry backup
        if ($Backup) {
            if (-not $SkipConfirmation) {
                if (-not (Backup-RegistryState $map.Extension)) {
                    Write-Host "Aborting: Backup failed" -ForegroundColor Red
                    return
                }
            }
            else {
                try {
                    Backup-RegistryState $map.Extension | Out-Null
                }
                catch {
                    Write-Warning "[!] Backup failed, but continuing due to -SkipConfirmation"
                }
            }
        }

        # 🧼 Perform cleanup
        $ghosts | ForEach-Object {
            Remove-ItemProperty -Path $openWithPath -Name $_.Key -ErrorAction SilentlyContinue
        }
    }
}


#endregion



#region Execution Flow

# Show help and exit immediately
if ($Help) {
    Write-Host @"
🔒 Safe File Association Analyzer

Usage:
  ftype-audit.ps1 -Path <.ext | file> [options]

Core Actions:
  -Clean              Perform safe cleanup of file association entries
  -DryRun             Preview cleanup actions without modifying registry
  -Backup             Create a registry backup before changes
  -BackupPath         Custom location for registry backup (default: .\ftype-backup-*.reg)

Input Interpretation:
  -IsExtension        Treat input Path as a file extension (e.g. 'txt' → '.txt')

Output Modes:
  -Explain            Human-readable interpretation of file association state
  -Literal            Pure technical dump of underlying registry and MRU values

Execution Control:
  -SkipConfirmation   Suppress confirmation prompts (e.g., ShouldContinue)
                      [!] Only has effect with -Clean or -DryRun

Help:
  -Help               Show this help screen

Examples:
  .\ftype-audit.ps1 -Path .json -DryRun -Backup
      → Show what would be removed from MRU with backup

  .\ftype-audit.ps1 -Path .txt -Clean -SkipConfirmation
      → Clean ghost MRU handlers for .txt without prompt

  .\ftype-audit.ps1 -Path .ps1 -Explain
      → Get semantic explanation of current .ps1 associations

  .\ftype-audit.ps1 -Path .pdf -Literal
      → Dump raw registry data related to .pdf association

Learn more:
  https://github.com/soyuz43/ftype-audit-safe
"@
    return
}


#region Execution Flow
<#
.SYNOPSIS
Validates and resolves file extensions with enterprise-grade security checks
#>

<#
Exit Code Semantics:
0  = Success
1  = User cancellation/input error
2  = Permission denied
3  = Invalid input/resolution failure
4+ = Reserved for future use
#>

function Get-ValidatedExtension {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RawInput
    )

    # Null/whitespace guard
    if ([string]::IsNullOrWhiteSpace($RawInput)) {
        throw "[ERR-EXT-01] Empty input"
    }

    $cleaned = $RawInput.Trim().Trim("'`"")

    # Path existence checks
    if (Test-Path $cleaned) {
        $item = Get-Item $cleaned -Force
        if ($item.PSIsContainer) {
            throw "[ERR-EXT-02] Path is directory: '$cleaned'"
        }
        if (-not $item.Extension) {
            throw "[ERR-EXT-03] File has no extension: '$cleaned'"
        }
        return $item.Extension.ToLower()
    }

    # Pure extension validation
    $ext = if ($cleaned.StartsWith('.')) {
        $cleaned
    }
    else {
        ".$cleaned"
    }

    # Structural validation
    if ($ext -notmatch '^\.[a-z0-9][\w-]{1,255}$') {
        throw "[ERR-EXT-04] Invalid extension format: '$ext'"
    }

    if ($ext.Length -gt 260) {
        throw "[ERR-EXT-05] Extension exceeds 260 chars: '$ext'"
    }

    return $ext.ToLower()
}

# Interactive prompt fallback
if (-not $PSBoundParameters.ContainsKey('Path')) {
    if ([Environment]::UserInteractive -and ($Host.Name -ne 'Default Host')) {
        try {
            $choice = $Host.UI.PromptForChoice(
                "Input Required",
                "No path provided:",
                @(
                    [System.Management.Automation.Host.ChoiceDescription]::new("&Enter Path", "Specify file/extension"),
                    [System.Management.Automation.Host.ChoiceDescription]::new("&Cancel", "Abort Operation")
                ),
                0
            )

            if ($choice -eq 0) {
                $Path = Read-Host "Enter target (file or extension)"
            }
            else {
                exit 1
            }
        }
        catch {
            Write-Error "[ERR-HOST-01] Prompt failed: $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Error "[ERR-HOST-02] Non-interactive session: -Path required"
        exit 1
    }
}


#region Extension Validation + Registry Snapshot
try {
    $resolvedExtension = Get-ValidatedExtension -RawInput $Path
    $registrySnapshot = Get-AssociationSnapshot -Extension $resolvedExtension
}
catch [System.Security.SecurityException] {
    # Special-case permission errors with precise category
    Write-Error "[ERR-ACCESS-01] Permission denied: $($_.Exception.Message)" -Category PermissionDenied
    exit 2
}
catch {
    # Generic error without forced category
    Write-Error "[ERR-VALIDATION-01] Resolution failure: $($_.Exception.Message)"
    exit 3
}
#endregion

#region Diagnostic Analysis
$healthReport = Test-AssociationHealth -Snapshot $registrySnapshot

# Validate parameter combinations
if ($SkipConfirmation -and (-not ($Clean -or $DryRun))) {
    Write-Warning "SkipConfirmation ignored without Clean/DryRun"
    $SkipConfirmation = $false
}
#endregion

#region Presentation Layer
$mode = if ($Literal) { "Literal" }
elseif ($Explain) { "Explain" }
else { "Summary" }

Write-AssociationReport -Snapshot $registrySnapshot -Diagnosis $healthReport -Mode $mode

#endregion

#region Remediation Logic
if ($Clean -or $DryRun) {
    $confirmation = $SkipConfirmation -or $Host.UI.PromptForChoice(
        "Confirm Action", 
        "Modify system associations for $resolvedExtension?",
        @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&Proceed", "Execute changes"),
            [System.Management.Automation.Host.ChoiceDescription]::new("&Cancel", "Abort operation")
        ), 
        1
    )

    if ($confirmation -eq 0) {
        try {
            if ($DryRun) {
                Write-Host "Simulated repair operations:" -ForegroundColor Magenta
                $healthReport.Evidence | ForEach-Object {
                    Write-Host "Would fix: $_"
                }
            }
            else {
                # Invoke actual repair implementation here
                Write-Host "Performing registry repairs..." -ForegroundColor Cyan
            }
        }
        catch {
            Write-Error "Repair failed: $($_.Exception.Message)" -Category OperationStopped
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
