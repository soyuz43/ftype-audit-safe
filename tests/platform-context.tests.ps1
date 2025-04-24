BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '../src/platform/PlatformContext.ps1' -Resolve

    Write-Host "[DEBUG] Sourcing platform context from: $scriptPath"

    if (-not (Test-Path $scriptPath)) {
        throw "Cannot find PlatformContext.ps1 at: $scriptPath"
    }

    . $scriptPath
}


Describe "Get-PlatformContext [real environment]" {
    $ctx = Get-PlatformContext  # Capture once to avoid repeated calls
    $expectedKeys = @(
        'PowerShellEdition',
        'PowerShellMajor',
        'IsWindows',
        'IsElevated',
        'Is64BitOS',
        'Is64BitProcess'
    )

    foreach ($key in $expectedKeys) {
        It "Includes key: $key" {
            # Check if the property exists on the PSCustomObject
            $ctx.PSObject.Properties.Name | Should -Contain $key
        }
    }

    It "Reports PowerShell edition as 'Desktop' or 'Core'" {
        $ctx.PowerShellEdition | Should -Match "Desktop|Core"
    }

    It "Returns PowerShellMajor as Int32" {
        $ctx.PowerShellMajor | Should -BeOfType [int]
    }

    Context "Boolean Values" {
        It "IsWindows is Boolean" {
            $ctx.IsWindows | Should -BeOfType [bool]
        }

        It "IsElevated is Boolean" {
            $ctx.IsElevated | Should -BeOfType [bool]
        }
        
        It "Is64BitOS is Boolean" {
            $ctx.Is64BitOS | Should -BeOfType [bool]
        }
    }
}

Describe "Get-PlatformContext [simulated]" -Tag 'Mocked' {
    BeforeAll {
        Mock Test-IsElevated { $false }
        Mock Get-PlatformContext {
            [pscustomobject]@{
                PowerShellEdition = 'Core'
                PowerShellMajor   = 7
                IsWindows         = $true
                IsElevated        = $false
                Is64BitOS         = $true
                Is64BitProcess    = $false
            }
        }
    }

    It "Simulates non-elevated session" {
        $ctx = Get-PlatformContext
        $ctx.IsElevated | Should -BeFalse
    }

    It "Simulates 32-bit PowerShell on 64-bit OS" {
        $ctx = Get-PlatformContext
        $ctx.Is64BitOS | Should -BeTrue
        $ctx.Is64BitProcess | Should -BeFalse
    }
}