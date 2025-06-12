# src/FtypeAudit.psm1

# ── Platform Utilities ───────────────────────────────
. "$PSScriptRoot\platform\PlatformContext.ps1"

# ── Core Modules ─────────────────────────────────────
. "$PSScriptRoot\core\Diagnosis.ps1"
. "$PSScriptRoot\core\Snapshot.ps1"
. "$PSScriptRoot\core\Reporter.ps1"
. "$PSScriptRoot\core\Repair.ps1"
. "$PSScriptRoot\core\RegistryHelpers.ps1"

# ── Export Public API ────────────────────────────────
Export-ModuleMember -Function `
    Get-AssociationSnapshot,
    Test-AssociationHealth,
    Write-AssociationReport,
    Repair-Association
