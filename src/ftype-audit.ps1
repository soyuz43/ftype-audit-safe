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

.PARAMETER Backup
Create registry backup before making changes

.PARAMETER Force
Bypass confirmation prompts

.PARAMETER Literal
Display pure technical output without annotations

.EXAMPLE
Get-SafeAssociationProfile .pdf -Explain
Analyze PDF associations with technical explanation

.EXAMPLE
Invoke-AssociationClean .ps1 -Backup -DryRun
Preview PowerShell file association cleanup with safety backup

.NOTES
Author: William Stetar
Version: 1.0.0
Requires: PowerShell 5.1+

.LINK
https://github.com/soyuz43/ftype-audit-safe
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [string]$Path,

    [switch]$Explain,
    [switch]$DryRun,
    [switch]$Backup,
    [string]$BackupPath = ".\ftype-backup-$(Get-Date -Format yyyyMMdd-HHmmss).reg",
    [switch]$Force,
    [switch]$Literal,
    [switch]$Help
)
#region Elevation Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "⚠️ Running without elevation - some registry keys may be inaccessible"
}
#endregion

#region Initialization
$ErrorActionPreference = 'Stop'

class SafeAssociationProfile {
    [string]$Extension
    [string]$UserChoice
    [string]$ProgIdCommand
    [hashtable]$Handlers
    [string]$MRUList
    [bool]$IsCoherent
    [string]$SystemDefault
    [datetime]$LastModified
    [bool]$IsValid
}
#endregion

#region Core Functions
function Get-SafeSemioticMap {
    param($ext)
    
    $map = [SafeAssociationProfile]::new()
    $map.Extension = $ext
    $map.IsValid = $true

    # User Intent Layer
    try {
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
        if (Test-Path $userChoicePath) {
            $userChoice = Get-ItemProperty $userChoicePath -ErrorAction Stop
            if ($userChoice.ProgId -match '^(AppX[\w]+|\w+(\.\w+)*)$') {
                $map.UserChoice = $userChoice.ProgId
            
                # Optional: Add clarity if it's a UWP handler
                if ($map.UserChoice -match '^AppX') {
                    $map.UserChoice += " (UWP App - not resolved via HKCR)"
                }
            }
            else {
                $map.UserChoice = "<Invalid ProgId>"
                $map.IsValid = $false
            }
            
            $map.LastModified = (Get-Item $userChoicePath).LastWriteTime
        }
    }
    catch {
        $map.UserChoice = "<Access Denied>"
        $map.IsValid = $false
    }

    # System Truth Layer
    try {
        $sysDefault = (Get-ItemProperty "HKCR:\$ext" -ErrorAction Stop).'(default)'
        $map.SystemDefault = if ($sysDefault) { 
            $sysDefault 
        }
        else { 
            "<Empty>" 
        }

        # Mark AppX ProgIDs for UWP apps
        if ($map.SystemDefault -match '^AppX') {
            $map.SystemDefault += " (UWP App - may not have HKCR entry)"
        }
    }
    catch {
        $map.SystemDefault = "<Not Found>"
    }


    # Memory Layer (MRU)
    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\OpenWithList"
    if (Test-Path $openWithPath) {
        $openWith = Get-ItemProperty $openWithPath -ErrorAction SilentlyContinue
        $map.Handlers = @{}
        $openWith.PSObject.Properties | Where-Object { 
            $_.Name -match '^[a-z]$' 
        } | ForEach-Object {
            $exePath = try { 
                $cmd = Get-Command $_.Value -ErrorAction Stop
                $cmd.Source
            }
            catch { 
                $null 
            }
            $map.Handlers[$_.Name] = @{
                Exe    = $_.Value
                Exists = [bool]$exePath
                Path   = $exePath
            }
        }
        $map.MRUList = $openWith.MRUList
        
        # Coherence check
        $validMRU = $map.MRUList -replace '[^a-z]', ''
        $invalidCount = $validMRU.ToCharArray() | 
        ForEach-Object { -not $map.Handlers.ContainsKey($_) } |
        Where-Object { $_ -eq $true } |
        Measure-Object | Select-Object -ExpandProperty Count
        $map.IsCoherent = ($invalidCount -eq 0)
    }
    else {
        $map.IsCoherent = $false
        $map.IsValid = $false
    }

    $map
}

function Show-TechnicalReport {
    param($map)
    
    Write-Host "`n[Technical Analysis: $($map.Extension)]" -ForegroundColor Cyan
    Write-Host "----------------------------------------"
    
    Write-Host "User Choice ProgID: $($map.UserChoice)"
    Write-Host "System Default:     $($map.SystemDefault)"
    Write-Host "MRU List Validity:  $(if ($map.IsCoherent) {'Valid'} else {'Invalid'})"
    
    Write-Host "`nHandler Inventory:"
    $map.Handlers.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $status = if ($_.Value.Exists) { "OK" } else { "MISSING" }
        Write-Host "  $($_.Key): $($_.Value.Exe) [$status]"
    }
}

function Backup-RegistryState {
    param($ext)
    
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
    param($map)
    
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
        if ($Backup -and -not (Backup-RegistryState $map.Extension)) {
            Write-Host "Aborting: Backup failed" -ForegroundColor Red
            return
        }
        
        $ghosts | ForEach-Object {
            Remove-ItemProperty -Path $openWithPath -Name $_.Key -ErrorAction SilentlyContinue
        }
    }
}
#endregion

#region Execution Flow
if ($Help) {
    Write-Host @"
🔒 Safe File Association Analyzer

Usage:
  ftype-audit <path/extension> [options]

Safety-First Options:
  -DryRun         Preview changes without modification
  -Backup         Create registry backup before changes
  -BackupPath     Custom backup location (default: .\ftype-backup-*.reg)
  -Force          Bypass confirmation prompts

Analysis Modes:
  -Literal        Pure technical output
  -Explain        Show interpretation

Examples:
  ftype-audit .json -DryRun -Backup
  ftype-audit .txt -Literal
"@
    exit
}

# Input validation
if (-not $PSBoundParameters.ContainsKey('Path')) {
    $Path = Read-Host "Enter file path or extension to analyze"
}

$ext = if ([IO.Path]::GetExtension($Path)) { 
    [IO.Path]::GetExtension($Path) 
}
else { 
    if (-not $Path.StartsWith('.')) { ".$Path" } else { $Path } 
}

# Core analysis
$semioticMap = Get-SafeSemioticMap $ext

if ($Literal) {
    Show-TechnicalReport $semioticMap
}
else {
    # Show original cognitive report
}

if ($semioticMap.IsValid) {
    if ($Explain) {
        Write-Host "`n[Technical Interpretation]" -ForegroundColor Blue
        Write-Host @"
Association resolution flow:
1. Check UserChoice registry value
2. Fallback to system default ProgID
3. Use MRU list if no explicit defaults

Current state analysis:
- User explicit choice: $(if ($semioticMap.UserChoice) {'Set'} else {'Not set'})
- System fallback: $($semioticMap.SystemDefault)
- Valid handlers: $($semioticMap.Handlers.Values.Where({$_.Exists}).Count)
"@
    }

    if ($DryRun -or $Backup -or $Force) {
        Invoke-SafeClean $semioticMap
    }
}
else {
    Write-Host "Invalid registry state detected - manual intervention recommended" -ForegroundColor Red
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
