# tests/json-output.tests.ps1

Describe "Get-JsonSchemaVersion" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/JsonOutput.ps1')
    }

    It "Returns a positive integer version" {
        $version = Get-JsonSchemaVersion
        $version | Should -BeOfType [int]
        $version | Should -BeGreaterThan 0
    }
}

Describe "ConvertTo-EnumName" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/JsonOutput.ps1')
    }

    It "Returns the name of an enum value" {
        ConvertTo-EnumName ([System.DayOfWeek]::Monday) | Should -Be 'Monday'
    }

    It "Returns a string unchanged" {
        ConvertTo-EnumName 'alreadyText' | Should -Be 'alreadyText'
    }

    It "Returns an empty string for null" {
        ConvertTo-EnumName $null | Should -Be ''
    }
}

Describe "New-AuditJsonDocument" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
        . (Join-Path $PSScriptRoot '../src/core/JsonOutput.ps1')
    }

    It "Emits a document with the schema version and extension" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot

        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis

        $doc.schemaVersion | Should -Be (Get-JsonSchemaVersion)
        $doc.extension | Should -Be '.txt'
        $doc.healthy | Should -BeFalse
        $doc.issueCount | Should -BeGreaterThan 0
    }

    It "Excludes PowerShell provider metadata from openWithList" {
        # Regression: Get-ItemProperty returns a PSObject carrying provider
        # metadata (PSPath, PSDrive, PSParentPath, ...). Those leaked into the
        # JSON document as if they were registry values.
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $snapshot.RegistryValues.OpenWithList = [PSCustomObject]@{
            a       = 'chrome.exe'
            MRUList = 'a'
            PSPath  = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\...'
            PSDrive = 'HKCU'
            PSParentPath = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\...'
            PSChildName  = 'OpenWithList'
            PSProvider   = 'Microsoft.PowerShell.Core\Registry'
        }
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot

        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis

        $doc.registry.openWithList.Contains('a') | Should -BeTrue
        $doc.registry.openWithList.Contains('PSPath') | Should -BeFalse
        $doc.registry.openWithList.Contains('PSDrive') | Should -BeFalse
        $doc.registry.openWithList.Contains('PSProvider') | Should -BeFalse
        $doc.registry.openWithList.Contains('PSChildName') | Should -BeFalse
        # MRUList is surfaced separately, not mixed into the handler values.
        $doc.registry.openWithList.Contains('MRUList') | Should -BeFalse
        $doc.registry.mruList | Should -Be 'a'
    }

    It "Marks handlers as broken based on their resolution status" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.ghost'
        $snapshot.RegistryValues.OpenWithList = [PSCustomObject]@{
            e       = 'DefinitelyNotInstalledApp.exe'
            MRUList = 'e'
        }
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot
        $resolutions = Resolve-OpenWithListHandlers -Snapshot $snapshot

        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis -Resolutions $resolutions

        $doc.handlers.Count | Should -Be 1
        $doc.handlers[0].key | Should -Be 'e'
        $doc.handlers[0].isBroken | Should -BeTrue
        $doc.brokenHandlers | Should -Contain 'e'
    }

    It "Serializes to valid JSON that round-trips" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot

        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis
        $json = ConvertTo-AuditJson -Document $doc

        { $json | ConvertFrom-Json } | Should -Not -Throw
        $parsed = $json | ConvertFrom-Json
        $parsed.extension | Should -Be '.txt'
        $parsed.schemaVersion | Should -Be (Get-JsonSchemaVersion)
    }

    It "Emits enum states as names rather than ordinals" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot

        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis
        $json = ConvertTo-AuditJson -Document $doc

        # The state name must appear as text, not as its numeric ordinal.
        $json | Should -Match 'MissingUserChoice'
        $json | Should -Not -Match '"state"\s*:\s*0\b'
    }
}

Describe "Add-RepairPlanToJsonDocument" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
        . (Join-Path $PSScriptRoot '../src/core/HandlerResolver.ps1')
        . (Join-Path $PSScriptRoot '../src/core/Diagnosis.ps1')
        . (Join-Path $PSScriptRoot '../src/core/JsonOutput.ps1')
    }

    It "Records the planned removals and MRUList rewrite" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot
        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis

        $null = Add-RepairPlanToJsonDocument -Document $doc `
                                             -PlannedRemovals @('b') `
                                             -CurrentMruList 'afgbcde' `
                                             -PlannedMruList 'afgcde'

        $doc.repair.applied | Should -BeFalse
        $doc.repair.plannedRemovals | Should -Contain 'b'
        $doc.repair.currentMruList | Should -Be 'afgbcde'
        $doc.repair.plannedMruList | Should -Be 'afgcde'
        $doc.repair.mruListWillChange | Should -BeTrue
    }

    It "Marks the plan as applied when the repair ran" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot
        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis

        $null = Add-RepairPlanToJsonDocument -Document $doc `
                                             -PlannedRemovals @('b') `
                                             -CurrentMruList 'afgbcde' `
                                             -PlannedMruList 'afgcde' `
                                             -Applied

        $doc.repair.applied | Should -BeTrue
    }

    It "Reports no MRUList change when the lists match" {
        $snapshot = [AssociationSnapshot]::new()
        $snapshot.Extension = '.txt'
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot
        $doc = New-AuditJsonDocument -Snapshot $snapshot -Diagnosis $diagnosis

        $null = Add-RepairPlanToJsonDocument -Document $doc `
                                             -PlannedRemovals @() `
                                             -CurrentMruList 'afg' `
                                             -PlannedMruList 'afg'

        $doc.repair.mruListWillChange | Should -BeFalse
    }
}
