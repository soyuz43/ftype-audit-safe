# FtypeAudit

Secure File Association Management for Windows
Version 1.0.0 | MIT License
Repository: [https://github.com/soyuz43/ftype-audit-safe](https://github.com/soyuz43/ftype-audit-safe)

---

## Overview

FtypeAudit is a PowerShell toolkit for auditing and repairing Windows file association configuration.

It provides:

* Deterministic inspection of registry association layers
* Safe mutation controls with backup and simulation modes
* Structured output suitable for automation and reporting
* Separation of audit and repair operations

The tool is designed for controlled, reversible registry operations.

---

## Requirements

* Windows 10/11 or Windows Server 2016+
* PowerShell 5.1+
* Execution Policy: `RemoteSigned`
* Administrative privileges recommended for system-wide repair

---

## Installation

### Script Deployment

Download and execute locally:

```powershell
.\ftype-audit.ps1
```

### Module Installation

```powershell
Install-Module -Name FtypeAudit -Scope CurrentUser
Import-Module FtypeAudit
```

Manual installation:

```powershell
Copy-Item .\FtypeAudit -Destination $env:PSModulePath -Recurse
```

---

## Operational Model

FtypeAudit separates:

1. Audit (read-only analysis)
2. Simulation (dry-run repair preview)
3. Controlled repair (with optional backup)

Registry writes are never performed unless explicitly requested.

---

## Core Commands

### Inspect Associations

```powershell
Get-FileAssociation -Extension .pdf
Invoke-FullAssociationAudit -OutputFormat JSON
```

### Cleanup and Repair

```powershell
Clear-AssociationArtifacts -Extension .docx -Backup
Repair-FileHandlers -Extension .ps1 -Force
```

### Policy Export / Import

```powershell
Export-AssociationPolicy -Path .\policy.json
Import-AssociationPolicy -Path .\enterprise_rules.json
```

---

## Safety Controls

| Control              | Description                                     |
| -------------------- | ----------------------------------------------- |
| Dry-Run Mode         | Simulates changes without registry modification |
| Backup Mode          | Creates .reg snapshot before mutation           |
| Elevation Guard      | Warns when insufficient privileges detected     |
| Signature Validation | Verifies script authenticity                    |
| WhatIf Support       | Uses native PowerShell simulation semantics     |

Repairs are reversible when backup mode is enabled.

---

## Automation Integration

### Scheduled Audit

```powershell
Register-ScheduledJob -Name "DailyFtypeAudit" -ScriptBlock {
    Import-Module FtypeAudit
    Invoke-FullAssociationAudit |
    Export-Clixml "\\server\audits\$(Get-Date -Format yyyyMMdd).xml"
} -Trigger (New-JobTrigger -Daily -At 2AM)
```

### Pipeline Use

```powershell
Invoke-FullAssociationAudit -OutputFormat JSON |
    ConvertFrom-Json |
    Where-Object { $_.State -ne "Healthy" }
```

Non-zero exit codes should be implemented for CI integration.

---

## Security Considerations

* Always verify backups before repair.
* Validate script signature when running in restricted environments.
* Prefer user-scope audits before system-wide changes.
* Do not disable execution policies for convenience.

Example:

```powershell
Get-AuthenticodeSignature .\FtypeAudit.ps1
```

---

## Troubleshooting

### Access Denied

Run elevated:

```powershell
Start-Process powershell -Verb RunAs
```

### Restore Defaults

```powershell
Restore-DefaultHandlers -Extension .xlsx
```

### Validate Registry Store

```powershell
Test-AssociationStore -Scope AllUsers
```

---

## Scope

FtypeAudit manages Windows file association registry layers, including:

* UserChoice
* System defaults
* MRU ordering
* Handler resolution

It does not override Group Policy–enforced associations unless explicitly permitted.

---

## License

MIT License
Copyright (c) 2024 William Stetar

See LICENSE.md for full terms.
