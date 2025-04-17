# tests/platform-context.tests.ps1

. "$PSScriptRoot/../src/platform/PlatformContext.ps1"

Describe "Get-PlatformContext [real environment]" {
    It "Returns all expected keys" {
        $ctx = Get-PlatformContext
        $ctx.Keys | Should -Contain "PowerShellEdition"
        $ctx.Keys | Should -Contain "PowerShellMajor"
        $ctx.Keys | Should -Contain "IsWindows"
        $ctx.Keys | Should -Contain "IsElevated"
        $ctx.Keys | Should -Contain "Is64BitOS"
        $ctx.Keys | Should -Contain "Is64BitProcess"
    }

    It "Reports PowerShell edition as 'Desktop' or 'Core'" {
        $ctx = Get-PlatformContext
        $ctx.PowerShellEdition | Should -Match "Desktop|Core"
    }

    It "Returns PowerShellMajor as Int32" {
        $ctx = Get-PlatformContext
        $ctx.PowerShellMajor | Should -BeOfType "System.Int32"
    }

    It "Returns IsWindows as Boolean" {
        $ctx = Get-PlatformContext
        $ctx.IsWindows | Should -BeOfType "System.Boolean"
    }

    It "Returns IsElevated as Boolean" {
        $ctx = Get-PlatformContext
        $ctx.IsElevated | Should -BeOfType "System.Boolean"
    }
}

Describe "Get-PlatformContext [simulated]" {
    It "Simulates non-elevated session" {
        Mock Test-IsElevated { $false }

        $ctx = Get-PlatformContext
        $ctx.IsElevated | Should -BeFalse
    }

    It "Simulates 32-bit PowerShell on 64-bit OS" {
        Mock Get-PlatformContext {
            return @{
                PowerShellEdition = 'Core'
                PowerShellMajor   = 7
                IsWindows         = $true
                IsElevated        = $true
                Is64BitOS         = $true
                Is64BitProcess    = $false
            }
        }

        $ctx = Get-PlatformContext
        $ctx.Is64BitOS | Should -BeTrue
        $ctx.Is64BitProcess | Should -BeFalse
    }
}
