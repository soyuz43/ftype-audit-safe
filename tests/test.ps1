$config = New-PesterConfiguration
$config.Run.Path = 'tests'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
