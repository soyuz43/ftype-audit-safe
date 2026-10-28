# tests/mrulist.tests.ps1
# Coverage for the MRUList repair, which fixes the dangling references the
# original repair step left behind.

Describe "Get-CorrectedMruList" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/MruList.ps1')
    }

    It "Removes a letter whose handler was deleted" {
        Get-CorrectedMruList -CurrentMruList 'abc' -RemovedKeys @('b') | Should -Be 'ac'
    }

    It "Preserves the relative order of surviving letters" {
        # MRU order is recency, not key order, so it must not be re-sorted.
        Get-CorrectedMruList -CurrentMruList 'ajbcdefgh' -RemovedKeys @('i') | Should -Be 'ajbcdefgh'
    }

    It "Removes every deleted letter" {
        Get-CorrectedMruList -CurrentMruList 'afgbcde' -RemovedKeys @('a','f','g','b','c','e') | Should -Be 'd'
    }

    It "Returns an empty string when every letter is removed" {
        Get-CorrectedMruList -CurrentMruList 'ab' -RemovedKeys @('a','b') | Should -Be ''
    }

    It "Leaves an unrelated MRUList untouched" {
        Get-CorrectedMruList -CurrentMruList 'abc' -RemovedKeys @('z') | Should -Be 'abc'
    }

    It "Keeps gaps in the key list" {
        # .jpg on a real machine has keys a,b,c,d,e,f,g,i,k,h,j with
        # MRUList 'aecdb'. Gaps are normal and must not be closed up.
        Get-CorrectedMruList -CurrentMruList 'aecdb' -RemovedKeys @('c') | Should -Be 'aedb'
    }

    It "Returns an empty string for an empty MRUList" {
        Get-CorrectedMruList -CurrentMruList '' -RemovedKeys @('a') | Should -Be ''
    }

    It "De-duplicates repeated letters" {
        Get-CorrectedMruList -CurrentMruList 'aab' -RemovedKeys @() | Should -Be 'ab'
    }
}

Describe "Update-MruList" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/MruList.ps1')
    }

    It "Writes the corrected MRUList back to the key" {
        Mock Set-ItemProperty { }
        Mock Remove-ItemProperty { }

        Update-MruList -OpenWithPath 'HKCU:\Test\OpenWithList' `
                       -CurrentMruList 'abc' `
                       -RemovedKeys @('b') `
                       -Confirm:$false *>$null

        Should -Invoke -CommandName Set-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'MRUList' -and $Value -eq 'ac'
        }
    }

    It "Removes the MRUList value when no letters survive" {
        Mock Set-ItemProperty { }
        Mock Remove-ItemProperty { }

        Update-MruList -OpenWithPath 'HKCU:\Test\OpenWithList' `
                       -CurrentMruList 'ab' `
                       -RemovedKeys @('a','b') `
                       -Confirm:$false *>$null

        Should -Invoke -CommandName Remove-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'MRUList'
        }
        Should -Invoke -CommandName Set-ItemProperty -Times 0 -Exactly
    }

    It "Does not write when the MRUList is already consistent" {
        Mock Set-ItemProperty { }
        Mock Remove-ItemProperty { }

        Update-MruList -OpenWithPath 'HKCU:\Test\OpenWithList' `
                       -CurrentMruList 'abc' `
                       -RemovedKeys @('z') `
                       -Confirm:$false *>$null

        Should -Invoke -CommandName Set-ItemProperty -Times 0 -Exactly
        Should -Invoke -CommandName Remove-ItemProperty -Times 0 -Exactly
    }
}

Describe "Invoke-SafeClean repairs the MRUList" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
        . (Join-Path $PSScriptRoot '../src/core/MruList.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Repair.ps1')
        . (Join-Path $PSScriptRoot '../src/core/RegistryHelpers.ps1')
    }

    BeforeEach {
        $script:snap = [AssociationSnapshot]::new()
        $script:snap.Extension = '.ghost'
        $script:snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            e        = 'DefinitelyNotInstalledApp.exe'
            MRUList  = 'e'
        }
        $script:diag = Test-AssociationHealth -Snapshot $script:snap
    }

    It "Rewrites the MRUList after removing a dead handler" {
        # Regression: the repair removed the handler value but left MRUList
        # pointing at it, leaving a dangling reference that Windows never
        # cleans up on its own.
        Mock Remove-ItemProperty { }
        Mock Set-ItemProperty { }

        Invoke-SafeClean -Map $snap -Diagnosis $diag -Force -Confirm:$false *>$null

        # 'e' was the only letter, so MRUList is removed entirely rather than
        # left pointing at a value that no longer exists.
        Should -Invoke -CommandName Remove-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'MRUList'
        }
    }

    It "Keeps the surviving letters when only some handlers were removed" {
        $partial = [AssociationSnapshot]::new()
        $partial.Extension = '.partial'
        $partial.RegistryValues.OpenWithList = [PSCustomObject]@{
            e        = 'DefinitelyNotInstalledApp.exe'
            f        = 'notepad.exe'
            MRUList  = 'ef'
        }
        $partialDiag = Test-AssociationHealth -Snapshot $partial

        Mock Remove-ItemProperty { }
        Mock Set-ItemProperty { }

        Invoke-SafeClean -Map $partial -Diagnosis $partialDiag -Force -Confirm:$false *>$null

        Should -Invoke -CommandName Set-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'MRUList' -and $Value -eq 'f'
        }
    }

    It "Does not touch the MRUList when nothing was removed" {
        Mock Remove-ItemProperty { }
        Mock Set-ItemProperty { }

        $cleanSnap = [AssociationSnapshot]::new()
        $cleanSnap.Extension = '.ok'
        $cleanDiag = Test-AssociationHealth -Snapshot $cleanSnap

        Invoke-SafeClean -Map $cleanSnap -Diagnosis $cleanDiag -Force -Confirm:$false *>$null

        Should -Invoke -CommandName Set-ItemProperty -Times 0 -Exactly
    }

    It "Previews the MRUList rewrite during a dry run" {
        $information = @()
        Invoke-SafeClean -Map $snap -Diagnosis $diag -DryRun -Verbose *>&1 |
            ForEach-Object { $information += "$_" }

        ($information -join "`n") | Should -Match 'would remove MRUList'
    }
}

Describe "Backup-RegistryState" {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestFixtures.ps1')
        . (Join-Path $PSScriptRoot '../src/core/RegistryHelpers.ps1')
    }

    It "Reports failure for a key that does not exist" {
        # Regression: reg.exe exits non-zero for a missing key but does not
        # raise an exception, so the old implementation reported success and
        # wrote no backup file at all.
        $backupPath = Join-Path $env:TEMP 'ftaudit-test-missing.reg'
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue

        $result = Backup-RegistryState -ext '.zzzdefinitelynotexist' -BackupPath $backupPath

        $result | Should -BeFalse
        Test-Path -LiteralPath $backupPath | Should -BeFalse
    }

    It "Reports failure when the destination directory does not exist" {
        $backupPath = Join-Path $env:TEMP 'ftaudit-no-such-dir\backup.reg'

        $result = Backup-RegistryState -ext '.txt' -BackupPath $backupPath

        $result | Should -BeFalse
    }

    It "Creates a verifiable backup for a key that exists" {
        # A synthetic extension is used rather than '.txt'. The backup
        # exports the Explorer FileExts key for the extension, and whether
        # that key exists for '.txt' depends on the machine running the
        # test.
        $fixture = New-TestBrokenExtension
        $backupPath = Join-Path $env:TEMP 'ftaudit-test-ok.reg'
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue

        try {
            $result = Backup-RegistryState -ext $fixture.Extension -BackupPath $backupPath

            $result | Should -BeTrue
            Test-Path -LiteralPath $backupPath | Should -BeTrue
            Get-Content -LiteralPath $backupPath -TotalCount 1 |
                Should -Match '^Windows Registry Editor Version 5\.00'
        }
        finally {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
            Remove-TestFixture -Fixture $fixture
        }
    }

    It "Reports failure when the backup path is a directory" {
        # Regression: the stale-file cleanup used Remove-Item on the backup
        # path unconditionally. When that path was a directory, Remove-Item
        # raised a raw .NET NullReferenceException instead of returning $false,
        # so the caller saw a crash rather than a "backup failed" result.
        $backupPath = Join-Path $env:TEMP 'ftaudit-test-dir.reg'
        if (Test-Path -LiteralPath $backupPath) {
            Remove-Item -LiteralPath $backupPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $backupPath | Out-Null

        try {
            $fixture = New-TestBrokenExtension
            try {
                $result = Backup-RegistryState -ext $fixture.Extension -BackupPath $backupPath

                $result | Should -BeFalse
                # The directory must survive - a failed backup never removes it.
                Test-Path -LiteralPath $backupPath | Should -BeTrue
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }
        finally {
            Remove-Item -LiteralPath $backupPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

