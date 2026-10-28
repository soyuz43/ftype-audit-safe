# tests/handler-resolver.tests.ps1
# Coverage for HandlerResolver, which replaces the Test-Path/Get-Command
# heuristic that misclassified installed applications as broken handlers.

Describe "Split-HandlerCommand" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
    }

    It "Splits a quoted command line into executable and arguments" {
        $result = Split-HandlerCommand -Handler '"C:\Program Files\App\app.exe" -arg "%1"'

        $result.Executable | Should -Be 'C:\Program Files\App\app.exe'
        $result.Arguments | Should -Match '-arg'
    }

    It "Splits an unquoted command line on the first space" {
        $result = Split-HandlerCommand -Handler 'C:\Windows\System32\notepad.exe /pt "%1"'

        $result.Executable | Should -Be 'C:\Windows\System32\notepad.exe'
    }

    It "Keeps a bare name containing spaces intact" {
        # 'LM Studio.exe' and 'SD Prompt Reader.exe' are ProgIDs, not command
        # lines. Splitting on the first space would look up 'LM' and wrongly
        # report the handler as unregistered.
        $result = Split-HandlerCommand -Handler 'LM Studio.exe'

        $result.Executable | Should -Be 'LM Studio.exe'
        $result.Arguments | Should -Be ''
    }

    It "Returns a bare name unchanged" {
        $result = Split-HandlerCommand -Handler 'chrome.exe'

        $result.Executable | Should -Be 'chrome.exe'
        $result.Arguments | Should -Be ''
    }

    It "Returns an empty executable for whitespace input" {
        $result = Split-HandlerCommand -Handler '   '

        $result.Executable | Should -Be ''
    }
}

Describe "Get-ExecutableFromCommand" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
    }

    It "Extracts the executable from a quoted command" {
        Get-ExecutableFromCommand -Command '"C:\Apps\thing.exe" "%1"' |
            Should -Be 'C:\Apps\thing.exe'
    }

    It "Extracts the executable from an unquoted command" {
        Get-ExecutableFromCommand -Command 'C:\Apps\thing.exe -flag "%1"' |
            Should -Be 'C:\Apps\thing.exe'
    }

    It "Returns null for an empty command" {
        Get-ExecutableFromCommand -Command '' | Should -BeNullOrEmpty
    }
}

Describe "Resolve-HandlerTarget" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
    }

    Context "When the handler value is empty" {
        It "Reports the value as malformed" {
            $result = Resolve-HandlerTarget -Handler ''

            $result.Status | Should -Be ([HandlerResolution]::Malformed)
            $result.IsResolved() | Should -BeFalse
        }
    }

    Context "When the handler is an absolute path to an existing file" {
        It "Resolves it as a direct path" {
            $existing = (Get-Item (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')).FullName

            $result = Resolve-HandlerTarget -Handler $existing

            $result.Status | Should -Be ([HandlerResolution]::Resolved)
            $result.Method | Should -Be 'DirectPath'
            $result.ResolvedPath | Should -Be $existing
        }
    }

    Context "When the handler is an absolute path to a missing file" {
        It "Reports the target as missing" {
            $result = Resolve-HandlerTarget -Handler 'C:\definitely\not\here\missing.exe'

            $result.Status | Should -Be ([HandlerResolution]::TargetMissing)
            $result.IsResolved() | Should -BeFalse
        }
    }

    Context "When the handler is an unregistered ProgID" {
        It "Reports it as not registered" {
            $result = Resolve-HandlerTarget -Handler 'zzznotarealprogid999'

            $result.Status | Should -Be ([HandlerResolution]::NotRegistered)
            $result.IsResolved() | Should -BeFalse
            $result.Detail | Should -Match 'No ProgID registration found'
        }
    }

    Context "When the handler is an unregistered executable name" {
        It "Reports it as not registered" {
            $result = Resolve-HandlerTarget -Handler 'zzznotarealapp999.exe'

            $result.Status | Should -Be ([HandlerResolution]::NotRegistered)
            $result.Detail | Should -Match 'No application registration found'
        }
    }

    Context "When the handler is a registered executable" {
        It "Resolves it through the shell lookup chain" {
            # notepad.exe ships with Windows, so it is registered in App Paths
            # on every machine the test suite runs on.
            $result = Resolve-HandlerTarget -Handler 'notepad.exe'

            $result.Status | Should -Be ([HandlerResolution]::Resolved)
            $result.ResolvedPath | Should -Not -BeNullOrEmpty
            $result.Method | Should -Not -Be 'None'
        }
    }
}

Describe "Resolve-OpenWithListHandlers" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
    }

    It "Returns one result per OpenWithList letter" {
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = 'notepad.exe'
            b       = 'zzznotarealapp999.exe'
            MRUList = 'ab'
        }

        $results = Resolve-OpenWithListHandlers -Snapshot $snap

        $results.Keys.Count | Should -Be 2
        $results.ContainsKey('a') | Should -BeTrue
        $results.ContainsKey('b') | Should -BeTrue
    }

    It "Ignores the MRUList value" {
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = 'notepad.exe'
            MRUList = 'a'
        }

        $results = Resolve-OpenWithListHandlers -Snapshot $snap

        $results.Keys | Should -Not -Contain 'MRUList'
    }

    It "Returns an empty result when there is no OpenWithList" {
        $snap = [AssociationSnapshot]::new()

        $results = Resolve-OpenWithListHandlers -Snapshot $snap

        $results.Keys.Count | Should -Be 0
    }
}

Describe "Handler resolution in Test-AssociationHealth" {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestFixtures.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
    }

    It "Treats a registered but non-openable ProgID as inert, not broken" {
        # A real ProgID is registered here on purpose. The previous version
        # used 'txtfilelegacy', which happens to have only a 'printto' verb
        # on a typical Windows install - but that is a property of the host
        # machine, not of the code under test. On a clean CI runner the
        # ProgID may resolve differently, and the test failed there.
        $progId = New-TestProgIdWithVerb -Verb 'printto'
        try {
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = $progId
            MRUList = 'a'
        }

        $diag = Test-AssociationHealth -Snapshot $snap

        $diag.BrokenHandlerKeys | Should -Not -Contain 'a'
        $diag.InertHandlerKeys | Should -Contain 'a'
        # It gets its own state so it is not confused with a dead handler.
        $diag.Evidence.State | Should -Contain 'InertHandlerPath'
        $diag.Evidence.State | Should -Not -Contain 'BrokenHandlerPath'
        }
        finally {
            Remove-TestFixture -ProgId $progId
        }
    }

    It "Marks an unregistered ProgID as broken" {
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = 'zzznotarealprogid999'
            MRUList = 'a'
        }

        $diag = Test-AssociationHealth -Snapshot $snap

        $diag.BrokenHandlerKeys | Should -Contain 'a'
    }

    It "Accepts a hyphenated ProgID in UserChoice" {
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.UserChoice = [PSCustomObject]@{ ProgId = 'FirefoxPDF-CA9422711AE1A81C' }

        $diag = Test-AssociationHealth -Snapshot $snap

        $diag.Evidence.State | Should -Not -Contain 'InvalidProgIdSyntax'
    }

    It "Flags an MRU letter that references a removed value" {
        # The repair step removes a value but historically left MRUList intact,
        # producing a dangling reference that no handler backs.
        $snap = [AssociationSnapshot]::new()
        $snap.Extension = '.demo'
        $snap.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = 'notepad.exe'
            MRUList = 'az'
        }

        $diag = Test-AssociationHealth -Snapshot $snap

        $diag.Evidence.State | Should -Contain 'CorruptMRUOrder'
    }
}


