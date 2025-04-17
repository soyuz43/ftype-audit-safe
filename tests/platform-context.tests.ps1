BeforeAll {
    # Resolve platform context script path
    $scriptPath = Join-Path $PSScriptRoot '../src/platform/PlatformContext.ps1' -Resolve
    . $scriptPath
}

Describe "Get-PlatformContext [real environment]" {
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
            $ctx = Get-PlatformContext
            Write-Host "[DEBUG] ctx = $($ctx | Out-String)"
            It "Includes key: $key" {
    $ctx = Get-PlatformContext
    $ctx.ContainsKey($key) | Should -BeTrue
}
        }
    }
    It "Reports PowerShell edition as 'Desktop' or 'Core'" {
        $ctx = Get-PlatformContext
        $ctx.PowerShellEdition | Should -Match "Desktop|Core"
    }

    It "Returns PowerShellMajor as Int32" {
        (Get-PlatformContext).PowerShellMajor | Should -BeOfType [int]
    }

    Context "Boolean Values" {
        It "IsWindows is Boolean" {
            (Get-PlatformContext).IsWindows | Should -BeOfType [bool]
        }

        It "IsElevated is Boolean" {
            (Get-PlatformContext).IsElevated | Should -BeOfType [bool]
        }
        
        It "Is64BitOS is Boolean" {
            (Get-PlatformContext).Is64BitOS | Should -BeOfType [bool]
        }
    }
}

Describe "Get-PlatformContext [simulated]" -Tag 'Mocked' {
    BeforeAll {
        Mock Test-IsElevated { $false }
        Mock Get-PlatformContext {
            return [ordered]@{
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