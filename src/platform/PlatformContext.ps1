# src/platform/PlatformContext.ps1
# Provides cross-platform/environment metadata as a typed object

#region Elevation Detection
if (-not ([System.Management.Automation.PSTypeName]'Win32.TokenHelper').Type) {
    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;

    namespace Win32 {
        public class TokenHelper {
            [DllImport("advapi32.dll", SetLastError=true)]
            public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

            [DllImport("advapi32.dll", SetLastError=true)]
            public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInfoClass, out int TokenInfo, int TokenInfoLength, out int ReturnLength);
        }
    }
'@ -Language CSharp -ErrorAction Stop
}

function Test-IsElevated {
    try {
        $procHandle = [System.Diagnostics.Process]::GetCurrentProcess().Handle
        $tokenHandle = [IntPtr]::Zero
        [Win32.TokenHelper]::OpenProcessToken($procHandle, 0x8, [ref]$tokenHandle) | Out-Null
        $info = 0; $size = 0
        [Win32.TokenHelper]::GetTokenInformation($tokenHandle, 20, [ref]$info, 4, [ref]$size) | Out-Null
        return ($info -eq 2)
    } catch {
        Write-Host "[ERROR] Failed to determine elevation: $($_.Exception.Message)"
        return $false
    }
}
#endregion

function Get-PlatformContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Diagnostic logging.
    #
    # These used to be Write-Host calls, which wrote straight to the host
    # and therefore landed in stdout. That polluted the tool's output and
    # would corrupt any pipeline that parses stdout (the planned
    # -LiteralJson flag, for example). Write-Verbose keeps the same
    # information available under -Verbose while staying silent by default.
    Write-Verbose "PSEdition: $($PSVersionTable.PSEdition)"
    Write-Verbose "PSVersion.Major: $($PSVersionTable.PSVersion.Major)"
    Write-Verbose "OS Platform: $([System.Environment]::OSVersion.Platform)"
    Write-Verbose "Is64BitOS: $([Environment]::Is64BitOperatingSystem)"
    Write-Verbose "Is64BitProcess: $([Environment]::Is64BitProcess)"

    $isElevated = $false
    try {
        $isElevated = Test-IsElevated
    } catch {
        Write-Host "[ERROR] Elevation check failed: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        PowerShellEdition = $PSVersionTable.PSEdition
        PowerShellMajor   = $PSVersionTable.PSVersion.Major
        IsWindows         = ([System.Environment]::OSVersion.Platform -eq 'Win32NT')
        IsElevated        = $isElevated
        Is64BitOS         = [Environment]::Is64BitOperatingSystem
        Is64BitProcess    = [Environment]::Is64BitProcess
    }
}
