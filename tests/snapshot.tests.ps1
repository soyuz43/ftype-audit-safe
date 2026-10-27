# tests/snapshot.tests.ps1

Describe "Get-AssociationSnapshot" {
    BeforeAll {
        # Import the module/script that contains the class definition and function
        . (Join-Path $PSScriptRoot '../src/core/Snapshot.ps1')
    }

    Context "When no registry keys exist" {
        BeforeEach {
            Mock Test-Path          { $false }
            Mock Get-ItemProperty   { }  # Return nothing/null
            Mock Get-Item           { throw [System.Management.Automation.ItemNotFoundException]::new("Cannot find path") }
        }

        It "Returns an AssociationSnapshot object with default values" {
            $snap = Get-AssociationSnapshot -Extension .txt
            $snap.GetType().Name | Should -Be 'AssociationSnapshot'
            $snap.Extension        | Should -Be '.txt'
            $snap.RegistryValues.UserChoice    | Should -BeNullOrEmpty
            $snap.RegistryValues.SystemDefault | Should -BeNullOrEmpty
            $snap.RegistryValues.OpenWithList  | Should -BeNullOrEmpty
            $snap.HasData        | Should -BeFalse
        }
    }

    Context "When registry keys are present" {
        BeforeEach {
            Mock Test-Path {
                param($path) 
                return $true
            }
            Mock Get-ItemProperty {
                param($path)
                if ($path -like '*OpenWithList*') {
                    return [PSCustomObject]@{ a = 'handler1'; b = 'handler2' }
                }
                else {
                    return [PSCustomObject]@{ ProgId = 'txtfile' }
                }
            }
            Mock Get-Item {
                param($path)
                # Create a proper mock object with a ScriptMethod
                $mockKey = New-Object PSObject
                $mockKey | Add-Member -MemberType ScriptMethod -Name GetValue -Value { 
                    param($name) 
                    return 'sysfile' 
                }
                return $mockKey
            }
        }

        It "Populates UserChoice with ProgId" {
            $snap = Get-AssociationSnapshot -Extension .txt
            $snap.RegistryValues.UserChoice.ProgId | Should -Be 'txtfile'
        }

        It "Populates SystemDefault from default value" {
            $snap = Get-AssociationSnapshot -Extension .txt
            $snap.RegistryValues.SystemDefault | Should -Be 'sysfile'
        }

        It "Reads the system default from the merged HKEY_CLASSES_ROOT view" {
            # Regression: the snapshot used to read 'HKCR:\<ext>'. The HKCR
            # PSDrive is not mounted in PowerShell 7, and is absent in Windows
            # PowerShell 5.1 on this machine too, so Get-Item threw "Cannot
            # find drive" and the catch block swallowed it. SystemDefault was
            # always empty in live runs, which silently disabled the
            # UnregisteredProgId check downstream.
            #
            # The mock above returns the same object for any path, so it could
            # not catch this. Assert the path explicitly instead.
            $script:capturedPath = $null
            Mock Get-Item {
                param($path)
                $script:capturedPath = $path
                $mockKey = New-Object PSObject
                $mockKey | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                    param($name)
                    return 'sysfile'
                }
                return $mockKey
            }

            $null = Get-AssociationSnapshot -Extension .txt

            $script:capturedPath | Should -Not -Match '^HKCR:'
            $script:capturedPath | Should -Match '^Registry::HKEY_CLASSES_ROOT'
        }

        It "Populates OpenWithList entries" {
            $snap = Get-AssociationSnapshot -Extension .txt
            $snap.RegistryValues.OpenWithList.a | Should -Be 'handler1'
            $snap.RegistryValues.OpenWithList.b | Should -Be 'handler2'
        }

        It "Sets HasData to true when any key is found" {
            $snap = Get-AssociationSnapshot -Extension .txt
            $snap.HasData | Should -BeTrue
        }
    }

    Context "Extension normalization and timestamp" {
        It "Normalizes extension to lowercase" {
            $snap = Get-AssociationSnapshot -Extension '.MD'
            $snap.Extension | Should -Be '.md'
        }

        It "Accepts hyphenated and long extensions" {
            # Regression: the snapshot's ValidatePattern was
            # '^\.[a-z0-9]{1,10}$', which disagreed with the script's own
            # Get-ValidatedExtension ('^\.[A-Za-z0-9](?:[\w-]{0,254})$'). The
            # script accepted '.my-ext' and then the snapshot rejected it
            # with exit code 3 and a parameter-validation message.
            { Get-AssociationSnapshot -Extension '.my-ext' -ErrorAction Stop } | Should -Not -Throw
            { Get-AssociationSnapshot -Extension '.averyveryverylongextensionname' -ErrorAction Stop } | Should -Not -Throw
        }

        It "Sets LastChecked to a time within the last minute" {
            $snap = Get-AssociationSnapshot -Extension .txt
            ($snap.LastChecked -gt (Get-Date).AddMinutes(-1)) | Should -BeTrue
        }
    }
}
