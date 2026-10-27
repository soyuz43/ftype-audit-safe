# tests/python-cleanup.tests.ps1

Describe "Remove-ResidualPython confirmation" {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../src/cleanup/Python.ps1')
    }

    Context "When the user declines the deletion prompt" {
        It "Does not delete the path when the answer is 'n'" {
            # Regression: the condition used to be
            #
            #     -not (Read-Host ...) -match '^y(es)?$'
            #
            # PowerShell parses that as '(-not $Answer) -match ...'. '-not'
            # binds tighter than '-match', so the expression was always $false
            # and the "skip" branch was unreachable - answering "n" deleted
            # the path anyway.
            $fakeTarget = Join-Path $env:TEMP 'ftaudit-py-confirm-test'

            try {
                # Pretend the target exists, and answer "n" at the prompt.
                Mock Test-Path { $true }
                Mock Read-Host { 'n' }
                Mock Remove-Item { }

                Remove-ResidualPython -Confirm

                Should -Invoke Remove-Item -Times 0 -Exactly
            }
            finally {
                # Remove-Item is mocked inside the test, so the cleanup has to
                # call the cmdlet's real implementation directly. Calling
                # Remove-Item here would hit the mock and silently do
                # nothing, leaking the temp directory.
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fakeTarget `
                    -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It "Does not delete the path when the answer is empty" {
            Mock Test-Path { $true }
            Mock Read-Host { '' }
            Mock Remove-Item { }

            Remove-ResidualPython -Confirm

            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It "Deletes the path when the answer is 'y'" {
            Mock Test-Path { $true }
            Mock Read-Host { 'y' }
            Mock Remove-Item { }

            Remove-ResidualPython -Confirm

            Should -Invoke Remove-Item -Times 2 -Exactly
        }
    }
}
