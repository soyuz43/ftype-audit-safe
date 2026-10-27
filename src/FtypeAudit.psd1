@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'FtypeAudit.psm1'

    # Version number of this module.
    ModuleVersion = '1.3.0'

    # ID used to uniquely identify this module
    GUID = 'd43c7a7b-9a8a-40d5-8723-f9e8a4c21b75'

    # Author of this module
    Author = 'William Stetar'

    # Company or vendor of this module
    CompanyName = 'N/A'

    # Description of the functionality provided by this module
    Description = 'Safely audit and repair Windows file association configurations.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-AssociationSnapshot',
        'Resolve-HandlerTarget',
        'Test-AssociationHealth',
        'Write-AssociationReport',
        'Invoke-SafeClean',
        'Invoke-AuditRun',
        'Invoke-AssociationAudit',
        'Resolve-ExtensionList',
        'New-AuditJsonDocument',
        'Add-RepairPlanToJsonDocument',
        'ConvertTo-AuditJson',
        'Get-JsonSchemaVersion',
        'Get-AuditExitCode',
        'Get-WorstExitCode'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('FileAssociation', 'PowerShell', 'Registry', 'Security', 'Audit')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/soyuz43/ftype-audit-safe'
            IconUri = ''
            ReleaseNotes = 'Automation support: -Json emits a machine-readable document with a stable schema version, -OutputPath writes it to a file, -FailOnIssues turns a finding into a non-zero exit code for CI gating, and -Path now accepts a comma-separated list of extensions. The exit code contract distinguishes a failed audit from a finding.'
        }
    }
}
