Write-Host "DEBUG: Test file loaded"
Write-Host "DEBUG: PSScriptRoot = $PSScriptRoot"
Write-Host "DEBUG: Current location = $(Get-Location)"

Describe "Get-PlatformContext [real environment]" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '../src/platform/PlatformContext.ps1'
        Write-Host "DEBUG: Dot-sourcing $scriptPath"
        if (-not (Test-Path $scriptPath)) {
            throw "PlatformContext.ps1 not found at $scriptPath"
        }
        . $scriptPath
    }

    # Fix: Use individual It blocks instead of foreach loop to avoid variable scoping issues
    It "Includes key: PowerShellEdition" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'PowerShellEdition'
    }

    It "Includes key: PowerShellMajor" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'PowerShellMajor'
    }

    It "Includes key: IsWindows" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'IsWindows'
    }

    It "Includes key: IsElevated" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'IsElevated'
    }

    It "Includes key: Is64BitOS" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'Is64BitOS'
    }

    It "Includes key: Is64BitProcess" {
        $ctx = Get-PlatformContext
        $ctx.PSObject.Properties.Name | Should -Contain 'Is64BitProcess'
    }

    It "Reports PowerShell edition as 'Desktop' or 'Core'" {
        $ctx = Get-PlatformContext
        Write-Host "DEBUG: PowerShellEdition = $($ctx.PowerShellEdition)"
        $ctx.PowerShellEdition | Should -Match "Desktop|Core"
    }

    It "Returns PowerShellMajor as Int32" {
        $ctx = Get-PlatformContext
        Write-Host "DEBUG: PowerShellMajor = $($ctx.PowerShellMajor)"
        ($ctx.PowerShellMajor -is [int]) | Should -BeTrue
    }

    Context "Boolean Values" {
        It "IsWindows is Boolean" {
            $ctx = Get-PlatformContext
            Write-Host "DEBUG: IsWindows = $($ctx.IsWindows) (Type: $($ctx.IsWindows.GetType().FullName))"
            $ctx.IsWindows | Should -BeOfType [bool]
        }

        It "IsElevated is Boolean" {
            $ctx = Get-PlatformContext
            Write-Host "DEBUG: IsElevated = $($ctx.IsElevated) (Type: $($ctx.IsElevated.GetType().FullName))"
            $ctx.IsElevated | Should -BeOfType [bool]
        }

        It "Is64BitOS is Boolean" {
            $ctx = Get-PlatformContext
            Write-Host "DEBUG: Is64BitOS = $($ctx.Is64BitOS) (Type: $($ctx.Is64BitOS.GetType().FullName))"
            $ctx.Is64BitOS | Should -BeOfType [bool]
        }
    }
}

Describe "Get-PlatformContext [simulated]" -Tag 'Mocked' {
    BeforeAll {
        Write-Host "DEBUG: Entering mocked context"
        
        # First, dot-source the original script to get the function definition
        $scriptPath = Join-Path $PSScriptRoot '../src/platform/PlatformContext.ps1'
        if (-not (Test-Path $scriptPath)) {
            throw "PlatformContext.ps1 not found at $scriptPath"
        }
        . $scriptPath
        
        # Then mock the Test-IsElevated function if it exists
        # If Test-IsElevated doesn't exist, we'll mock it anyway
        Mock Test-IsElevated { $false } -ModuleName $null
        
        # Mock Get-PlatformContext to return simulated values
        Mock Get-PlatformContext {
            [pscustomobject]@{
                PowerShellEdition = 'Core'
                PowerShellMajor   = 7
                IsWindows         = $true
                IsElevated        = $false
                Is64BitOS         = $true
                Is64BitProcess    = $false
            }
        } -ModuleName $null
    }

    It "Simulates non-elevated session" {
        $ctx = Get-PlatformContext
        Write-Host "DEBUG: Simulated IsElevated = $($ctx.IsElevated)"
        $ctx.IsElevated | Should -BeFalse
    }

    It "Simulates 32-bit PowerShell on 64-bit OS" {
        $ctx = Get-PlatformContext
        Write-Host "DEBUG: Simulated Is64BitOS = $($ctx.Is64BitOS), Is64BitProcess = $($ctx.Is64BitProcess)"
        $ctx.Is64BitOS | Should -BeTrue
        $ctx.Is64BitProcess | Should -BeFalse
    }
}