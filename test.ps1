$requiredVersion = [Version]"5.0"

$active = (Get-Module Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1)

if ($active.Version -lt $requiredVersion) {
    throw "Pester $($requiredVersion) or higher is required, but $($active.Version) is installed."
}

Import-Module Pester -RequiredVersion $active.Version

Invoke-Pester -Configuration (Import-PowerShellDataFile '.config/PesterConfiguration.psd1')
