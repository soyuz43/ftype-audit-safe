# tests/exit-code.tests.ps1

Describe "Get-AuditExitCode" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/ExitCode.ps1')
    }

    It "Returns Success when the diagnosis has no evidence" {
        $diagnosis = [PSCustomObject]@{ Evidence = @() }
        Get-AuditExitCode -Diagnosis $diagnosis | Should -Be ([int][AuditExitCode]::Success)
    }

    It "Returns IssuesFound when the diagnosis has evidence" {
        $diagnosis = [PSCustomObject]@{
            Evidence = @([PSCustomObject]@{ State = 'BrokenHandlerPath'; Message = 'x' })
        }
        Get-AuditExitCode -Diagnosis $diagnosis | Should -Be ([int][AuditExitCode]::IssuesFound)
    }

    It "Returns Success for a null diagnosis" {
        Get-AuditExitCode -Diagnosis $null | Should -Be ([int][AuditExitCode]::Success)
    }
}

Describe "Get-WorstExitCode" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/ExitCode.ps1')
    }

    It "Returns Success for an empty list" {
        Get-WorstExitCode -ExitCodes @() | Should -Be ([int][AuditExitCode]::Success)
    }

    It "Returns Success when every code is Success" {
        Get-WorstExitCode -ExitCodes @(0, 0, 0) | Should -Be ([int][AuditExitCode]::Success)
    }

    It "Reports IssuesFound when the only non-zero code is a finding" {
        Get-WorstExitCode -ExitCodes @(0, 4, 0) | Should -Be ([int][AuditExitCode]::IssuesFound)
    }

    It "Prefers an operation failure over a finding" {
        # An operation failure means the state is unknown, which is worse
        # than a known problem.
        Get-WorstExitCode -ExitCodes @(4, 1) | Should -Be ([int][AuditExitCode]::OperationFailed)
    }

    It "Prefers a validation failure over a finding" {
        Get-WorstExitCode -ExitCodes @(4, 3) | Should -Be ([int][AuditExitCode]::ValidationFailure)
    }

    It "Prefers a registry access failure over a finding" {
        Get-WorstExitCode -ExitCodes @(4, 2) | Should -Be ([int][AuditExitCode]::RegistryAccessFailure)
    }

    It "Reports the operation failure even when it comes last" {
        Get-WorstExitCode -ExitCodes @(3, 4, 1) | Should -Be ([int][AuditExitCode]::OperationFailed)
    }
}

Describe "AuditExitCode contract" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/ExitCode.ps1')
    }

    It "Keeps the documented numeric values stable" {
        # Consumers switch on these numbers, so they must not be reused
        # for a different meaning.
        [int][AuditExitCode]::Success | Should -Be 0
        [int][AuditExitCode]::OperationFailed | Should -Be 1
        [int][AuditExitCode]::RegistryAccessFailure | Should -Be 2
        [int][AuditExitCode]::ValidationFailure | Should -Be 3
        [int][AuditExitCode]::IssuesFound | Should -Be 4
        [int][AuditExitCode]::UnsupportedEnvironment | Should -Be 5
    }
}

Describe "Resolve-ExtensionList" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/AuditRun.ps1')
    }

    It "Normalizes a single extension" {
        $result = Resolve-ExtensionList -Inputs @('txt') -Resolver { param($x) ".$x" }
        $result.Extensions | Should -Be '.txt'
        $result.Errors.Count | Should -Be 0
    }

    It "Splits a comma-separated list" {
        $result = Resolve-ExtensionList -Inputs @('.txt,.pdf') -Resolver { param($x) $x }
        $result.Extensions | Should -Be @('.txt', '.pdf')
    }

    It "Deduplicates repeated extensions" {
        $result = Resolve-ExtensionList -Inputs @('.txt,.txt') -Resolver { param($x) $x }
        $result.Extensions.Count | Should -Be 1
    }

    It "Records an invalid input as an error instead of aborting" {
        # A typo in one entry of a bulk list must not shrink the scope of
        # the whole audit.
        $result = Resolve-ExtensionList -Inputs @('.txt,bad!,.pdf') -Resolver {
            param($x)
            if ($x -eq 'bad!') { throw 'invalid' }
            $x
        }
        $result.Extensions | Should -Be @('.txt', '.pdf')
        $result.Errors.Count | Should -Be 1
        $result.Errors[0].input | Should -Be 'bad!'
    }

    It "Skips empty entries" {
        $result = Resolve-ExtensionList -Inputs @('', '  ', '.txt') -Resolver { param($x) $x }
        $result.Extensions | Should -Be @('.txt')
        $result.Errors.Count | Should -Be 0
    }
}

Describe "Invoke-AuditRun" {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestFixtures.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
        . (Join-Path $PSScriptRoot '../src/core/ExitCode.ps1')
        . (Join-Path $PSScriptRoot '../src/core/AuditRun.ps1')
    }

    It "Returns a result for each extension" {
        $fixture = New-TestBrokenExtension
        try {
            $run = Invoke-AuditRun -Extensions @($fixture.Extension, '.pdf')

            $run.Results.Count | Should -Be 2
            $run.Failures.Count | Should -Be 0
        }
        finally {
            Remove-TestFixture -Fixture $fixture
        }
    }

    It "Combines the exit codes across extensions" {
        # A synthetic broken extension is used rather than a real one like
        # '.txt'. Whether '.txt' has issues depends on the machine running
        # the test, so asserting on it made this test fail on a clean CI
        # runner while passing on a developer machine.
        $fixture = New-TestBrokenExtension
        try {
            $run = Invoke-AuditRun -Extensions @($fixture.Extension)
            $run.ExitCode | Should -Be ([int][AuditExitCode]::IssuesFound)
        }
        finally {
            Remove-TestFixture -Fixture $fixture
        }
    }

    It "Reports the broken handler it found" {
        $fixture = New-TestBrokenExtension
        try {
            $run = Invoke-AuditRun -Extensions @($fixture.Extension)
            $run.Results[0].Diagnosis.BrokenHandlerKeys | Should -Contain $fixture.HandlerKey
        }
        finally {
            Remove-TestFixture -Fixture $fixture
        }
    }

    It "Returns Success for an empty extension list" {
        $run = Invoke-AuditRun -Extensions @()
        $run.Results.Count | Should -Be 0
        $run.ExitCode | Should -Be ([int][AuditExitCode]::Success)
    }
}
