@{
    Run = @{
        Path       = 'tests'     # Run all tests in this folder
        Exit       = $true       # Return non-zero exit code on failure
        PassThru   = $true       # Return test results object
    }

    Output = @{
        Verbosity = 'Detailed'   # Options: None, Minimal, Normal, Detailed, Diagnostic
    }

    TestResult = @{
        Enabled      = $true
        OutputPath   = 'test-results.xml'
        OutputFormat = 'NUnitXml'  # CI-friendly format
    }

    CodeCoverage = @{
        Enabled       = $true
        Path          = 'src'
        OutputPath    = 'coverage.xml'
        OutputFormat  = 'JaCoCo'  # Compatible with Codecov, Coveralls
        Recurse       = $true     # Scan subfolders
        IncludeFilter = @('*.ps1')
    }
}
