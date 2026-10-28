# tests/ftype-audit.tests.ps1
# End-to-end tests for the script front end.
#
# These invoke the script as a child process rather than dot-sourcing it,
# because the script calls exit. Dot-sourcing would terminate the Pester
# run itself.

Describe "ftype-audit.ps1 command line" {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestFixtures.ps1')
        $script:ScriptPath = Join-Path $PSScriptRoot '../src/ftype-audit.ps1'
        $script:ResolvedScriptPath = (Resolve-Path $script:ScriptPath).Path

        # Runs the script in a child process and returns the exit code and
        # the captured stdout/stderr.
        function Invoke-AuditScript {
            param(
                [string[]]$Arguments
            )
            $stdoutFile = [System.IO.Path]::GetTempFileName()
            $stderrFile = [System.IO.Path]::GetTempFileName()
            try {
                # Start-Process -ArgumentList joins the array with spaces and
                # does not quote the individual elements, so an argument
                # containing a space ('bad ext!') would be split into two.
                # Quote each argument explicitly.
                $quoted = @('-NoProfile', '-File', ('"{0}"' -f $script:ResolvedScriptPath))
                foreach ($arg in $Arguments) {
                    $quoted += ('"{0}"' -f ($arg -replace '"', '\"'))
                }
                $process = Start-Process -FilePath 'pwsh' `
                    -ArgumentList $quoted `
                    -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
                return [PSCustomObject]@{
                    ExitCode = $process.ExitCode
                    StdOut   = (Get-Content -LiteralPath $stdoutFile -Raw)
                    StdErr   = (Get-Content -LiteralPath $stderrFile -Raw)
                }
            }
            finally {
                Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "JSON output" {
        It "Emits a parseable JSON document" {
            $result = Invoke-AuditScript -Arguments @('.txt', '-Json')

            { $result.StdOut | ConvertFrom-Json } | Should -Not -Throw
            $doc = $result.StdOut | ConvertFrom-Json
            $doc.schemaVersion | Should -BeGreaterThan 0
            $doc.extensions.Count | Should -Be 1
            $doc.extensions[0].extension | Should -Be '.txt'
        }

        It "Keeps stdout free of anything but the JSON document" {
            # The elevation notice used to be rendered into stdout, which
            # made the document unparseable.
            $result = Invoke-AuditScript -Arguments @('.txt', '-Json')

            $result.StdOut.TrimStart().StartsWith('{') | Should -BeTrue
            { $result.StdOut | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Reports the audit outcome separately from the process exit code" {
            # A synthetic broken extension is used rather than '.txt'.
            # Whether '.txt' has issues depends on the machine running the
            # test, so asserting on it made this test fail on a clean CI
            # runner while passing on a developer machine.
            $fixture = New-TestBrokenExtension
            try {
                $result = Invoke-AuditScript -Arguments @($fixture.Extension, '-Json')
                $doc = $result.StdOut | ConvertFrom-Json

                $doc.exitCode | Should -Be 4
                $doc.processExitCode | Should -Be 0
                $result.ExitCode | Should -Be 0
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }

        It "Writes the document to a file when -OutputPath is given" {
            $outFile = Join-Path $env:TEMP ("ftaudit-json-{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                $null = Invoke-AuditScript -Arguments @('.txt', '-Json', '-OutputPath', $outFile)

                Test-Path -LiteralPath $outFile | Should -BeTrue
                $doc = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
                $doc.extensions[0].extension | Should -Be '.txt'
            }
            finally {
                Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
            }
        }

        It "Rejects an output path in a directory that does not exist" {
            $result = Invoke-AuditScript -Arguments @('.txt', '-Json', '-OutputPath', (Join-Path $env:TEMP 'no-such-dir-here\out.json'))
            $result.ExitCode | Should -Not -Be 0
        }
    }

    Context "Bulk mode" {
        It "Audits every extension in a comma-separated list" {
            $result = Invoke-AuditScript -Arguments @('.txt,.pdf', '-Json')
            $doc = $result.StdOut | ConvertFrom-Json

            $doc.extensions.Count | Should -Be 2
            ($doc.extensions | ForEach-Object { $_.extension }) | Should -Contain '.txt'
            ($doc.extensions | ForEach-Object { $_.extension }) | Should -Contain '.pdf'
        }

        It "Reports the failing extension but still audits the others" {
            # 'not-an-ext' is a valid extension format - hyphens are allowed -
            # so only 'bad!' is rejected.
            $result = Invoke-AuditScript -Arguments @('.txt,bad!,not-an-ext', '-Json')
            $doc = $result.StdOut | ConvertFrom-Json

            # The valid extension is still audited.
            ($doc.extensions | ForEach-Object { $_.extension }) | Should -Contain '.txt'
            ($doc.extensions | ForEach-Object { $_.extension }) | Should -Contain '.not-an-ext'
            # The invalid one is reported rather than aborting the run.
            $doc.invalidInputs.Count | Should -Be 1
            ($doc.invalidInputs | ForEach-Object { $_.input }) | Should -Contain 'bad!'
            # A skipped input is not a failed audit.
            $doc.failures.Count | Should -Be 0
            # The run as a whole still succeeded.
            $result.ExitCode | Should -Be 0
        }
    }

    Context "JSON with a dry run" {
        It "Emits parseable JSON and includes the repair plan" {
            # Regression: the dry-run preview written by Invoke-SafeClean went
            # to stdout, which made the JSON document unparseable.
            $fixture = New-TestBrokenExtension
            try {
                $result = Invoke-AuditScript -Arguments @($fixture.Extension, '-DryRun', '-Json')

                { $result.StdOut | ConvertFrom-Json } | Should -Not -Throw
                $doc = $result.StdOut | ConvertFrom-Json
                $doc.mode | Should -Be 'dryRun'
                $doc.extensions[0].repair.applied | Should -BeFalse
                $doc.extensions[0].repair.plannedRemovals | Should -Contain $fixture.HandlerKey
                $doc.extensions[0].repair.currentMruList | Should -Be $fixture.HandlerKey
                # The fixture has a single handler and it is the one being
                # removed, so no MRU letter survives. The plan is to drop the
                # MRUList value entirely, which is why the planned value is
                # empty rather than the original letter.
                $doc.extensions[0].repair.plannedMruList | Should -Be ''
                $doc.extensions[0].repair.mruListWillChange | Should -BeTrue
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }

        It "Does not modify the registry" {
            $fixture = New-TestBrokenExtension
            try {
                $before = Get-Item -LiteralPath $fixture.OpenWithPath
                $beforeValue = $before.GetValue($fixture.HandlerKey)
                $beforeMru = $before.GetValue('MRUList')

                $null = Invoke-AuditScript -Arguments @($fixture.Extension, '-DryRun', '-Json')

                $after = Get-Item -LiteralPath $fixture.OpenWithPath
                $after.GetValue($fixture.HandlerKey) | Should -Be $beforeValue
                $after.GetValue('MRUList') | Should -Be $beforeMru
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }
    }

    Context "Exit codes" {
        It "Exits 0 when issues are found but -FailOnIssues is not set" {
            $fixture = New-TestBrokenExtension
            try {
                $result = Invoke-AuditScript -Arguments @($fixture.Extension)
                $result.ExitCode | Should -Be 0
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }

        It "Exits 4 when issues are found and -FailOnIssues is set" {
            $fixture = New-TestBrokenExtension
            try {
                $result = Invoke-AuditScript -Arguments @($fixture.Extension, '-FailOnIssues')
                $result.ExitCode | Should -Be 4
            }
            finally {
                Remove-TestFixture -Fixture $fixture
            }
        }

        It "Exits 3 when the extension is invalid" {
            $result = Invoke-AuditScript -Arguments @('bad ext!')
            $result.ExitCode | Should -Be 3
        }
    }
}
