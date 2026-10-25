# tests/diagnosis-repair.tests.ps1
# Regression coverage for Diagnosis (health checks) and Repair (safe clean),
# including the ghost-handler key plumbing that -Clean relies on.

Describe "Test-AssociationHealth" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
    }

    Context "When UserChoice is missing" {
        It "Registers MissingUserChoice evidence" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.txt'

            $diag = Test-AssociationHealth -Snapshot $snap

            $diag.Evidence.State | Should -Contain 'MissingUserChoice'
            $diag.HasIssues() | Should -BeTrue
        }
    }

    Context "When ProgId syntax is invalid" {
        It "Registers InvalidProgIdSyntax evidence" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.txt'
            $snap.RegistryValues.UserChoice = [PSCustomObject]@{ ProgId = '!!!bad progid!!!' }

            $diag = Test-AssociationHealth -Snapshot $snap

            $diag.Evidence.State | Should -Contain 'InvalidProgIdSyntax'
        }
    }

    Context "Handler resolution (Phase 3)" {
        It "Records BrokenHandlerPath evidence AND the OpenWithList key" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.ghost'
            # A handler that exists neither on disk nor as a command
            $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
                e        = 'DefinitelyNotInstalledApp.exe'
                MRUList  = 'e'
            }

            $diag = Test-AssociationHealth -Snapshot $snap

            $broken = $diag.Evidence | Where-Object State -eq 'BrokenHandlerPath'
            $broken | Should -Not -BeNullOrEmpty
            # The machine-readable key must be captured for Repair to use
            $diag.BrokenHandlerKeys | Should -Contain 'e'
        }

        It "Populates HandlerPaths for resolvable handlers" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.txt'
            # 'pwsh'/'powershell' resolves via Get-Command on any platform CI runs on;
            # fall back to dot-sourcing an existing file path so Test-Path succeeds.
            $self = (Get-Item (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')).FullName
            $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
                a        = $self   # existing file => Test-Path true
                MRUList  = 'a'
            }

            $diag = Test-AssociationHealth -Snapshot $snap

            $snap.HandlerPaths['a'] | Should -Be $self
            $diag.BrokenHandlerKeys.Count | Should -Be 0
        }
    }

    Context "MRU coherence (Phase 4)" {
        It "Flags MRU entries referencing broken handlers" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.ghost'
            $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
                a        = 'NoSuchApp.exe'
                MRUList  = 'a'
            }

            $diag = Test-AssociationHealth -Snapshot $snap

            $diag.Evidence.State | Should -Contain 'CorruptMRUOrder'
        }

        It "Does not flag MRU when all handlers resolve" {
            $snap = [AssociationSnapshot]::new()
            $snap.Extension = '.txt'
            $self = (Get-Item (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')).FullName
            $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
                a        = $self
                MRUList  = 'a'
            }

            $diag = Test-AssociationHealth -Snapshot $snap

            $diag.Evidence.State | Should -Not -Contain 'CorruptMRUOrder'
        }
    }
}

Describe "Invoke-SafeClean" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Repair.ps1')
        . (Join-Path $PSScriptRoot '../src/core/RegistryHelpers.ps1')
    }

    BeforeEach {
        # Build a snapshot + diagnosis with exactly one ghost handler under key 'e'
        $script:snap = [AssociationSnapshot]::new()
        $script:snap.Extension = '.ghost'
        $script:snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            e        = 'DefinitelyNotInstalledApp.exe'
            MRUList  = 'e'
        }
        $script:diag = Test-AssociationHealth -Snapshot $script:snap
    }

    It "DryRun reports the ghost key it would remove (regression: previously found nothing)" {
        $information = @()
        Invoke-SafeClean -Map $snap -Diagnosis $diag -DryRun -Verbose *>&1 |
            ForEach-Object { $information += "$_" }

        ($information -join "`n") | Should -Match 'would remove handler key: e'
    }

    It "DryRun performs no registry writes" {
        Mock Remove-ItemProperty { }

        Invoke-SafeClean -Map $snap -Diagnosis $diag -DryRun *>$null

        Should -Invoke -CommandName Remove-ItemProperty -Times 0 -Exactly
    }

    It "Clean removes exactly the broken handler keys (mocked registry)" {
        Mock Remove-ItemProperty { }

        Invoke-SafeClean -Map $snap -Diagnosis $diag -Force -Confirm:$false *>$null

        Should -Invoke -CommandName Remove-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'e'
        }
    }

    It "Clean skips removal when there are no broken handlers" {
        $cleanSnap = [AssociationSnapshot]::new()
        $cleanSnap.Extension = '.ok'
        Mock Remove-ItemProperty { }

        # No OpenWithList at all => no ghosts
        $cleanDiag = Test-AssociationHealth -Snapshot $cleanSnap

        Invoke-SafeClean -Map $cleanSnap -Diagnosis $cleanDiag -Force -Confirm:$false *>$null

        Should -Invoke -CommandName Remove-ItemProperty -Times 0 -Exactly
    }

    It 'Aborts actual cleanup when backup fails and -Force is not set' {
        Mock Backup-RegistryState { throw 'access denied' }
        Mock Remove-ItemProperty { }

        # Invoke-SafeClean signals the abort by throwing; ensure it does,
        # and that no registry writes happened before the abort.
        { Invoke-SafeClean -Map $snap -Diagnosis $diag -Backup -Force:$false -Confirm:$false -WhatIf:$false *>$null } |
            Should -Throw -ExpectedMessage '*Backup failed*'

        Should -Invoke -CommandName Remove-ItemProperty -Times 0 -Exactly
    }

    It 'Aborts cleanup when backup reports failure via return value (no exception)' {
        # Regression: Backup-RegistryState catches its own errors and RETURNS
        # $false instead of throwing. The old try/catch-only logic treated a
        # falsy return as success and silently cleaned with no backup at all.
        Mock Backup-RegistryState { return $false }
        Mock Remove-ItemProperty { }

        { Invoke-SafeClean -Map $snap -Diagnosis $diag -Backup -Confirm:$false *>$null } |
            Should -Throw -ExpectedMessage '*Backup failed*'

        Should -Invoke -CommandName Remove-ItemProperty -Times 0 -Exactly
    }

    It 'Continues cleanup after a backup failure when -Force is set' {
        Mock Backup-RegistryState { throw 'access denied' }
        Mock Remove-ItemProperty { }

        { Invoke-SafeClean -Map $snap -Diagnosis $diag -Backup -Force -Confirm:$false *>$null } |
            Should -Not -Throw

        Should -Invoke -CommandName Remove-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'e'
        }
    }

    It 'Cleans normally when backup succeeds' {
        Mock Backup-RegistryState { return $true }
        Mock Remove-ItemProperty { }

        { Invoke-SafeClean -Map $snap -Diagnosis $diag -Backup -Confirm:$false *>$null } |
            Should -Not -Throw

        Should -Invoke -CommandName Backup-RegistryState -Times 1 -Exactly
        Should -Invoke -CommandName Remove-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'e'
        }
    }
}
