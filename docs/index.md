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
$snapshot = Get-AssociationSnapshot -Extension '.pdf'
$diagnosis = Test-AssociationHealth -Snapshot $snapshot
Write-AssociationReport -Snapshot $snapshot -Diagnosis $diagnosis -Mode Explain
```

### Resolve a Single Handler

```powershell
Resolve-HandlerTarget -Handler 'chrome.exe'
Resolve-HandlerTarget -Handler 'VSCodium.json'
Resolve-HandlerTarget -Handler 'Microsoft.WindowsNotepad_8wekyb3d8bbwe!App'
```

Each call returns the target the shell would launch, the method used to find
it, and — when resolution fails — the reason.

### Cleanup and Repair

```powershell
Invoke-SafeClean -Map $snapshot -Diagnosis $diagnosis -DryRun
Invoke-SafeClean -Map $snapshot -Diagnosis $diagnosis -Backup
```

The script wrapper is a convenient front end for the same operations:

```powershell
.\src\ftype-audit.ps1 -Path .docx -DryRun
.\src\ftype-audit.ps1 -Path .docx -Clean -Backup
```

---


| Control              | Description                                     |
| -------------------- | ----------------------------------------------- |
| Dry-Run Mode         | Simulates changes without registry modification |
| Backup Mode          | Creates .reg snapshot before mutation           |
| Backup Failure       | Aborts the cleanup unless `-AllowBackupFailure` is set |
| Elevation Guard      | Warns when insufficient privileges detected     |
| Handler Resolution   | Follows the shell lookup chain, not file existence |
| WhatIf Support       | Uses native PowerShell simulation semantics     |

Repairs are reversible when backup mode is enabled.

`-SkipConfirmation` suppresses the interactive prompt only. It does **not**
weaken backup protection: if the backup cannot be written and verified, the
cleanup is aborted. Continuing past a failed backup requires the explicit
`-AllowBackupFailure` opt-in, which is off by default.

### MRUList Repair

The `OpenWithList` key carries an `MRUList` value — the handlers in
most-recently-used order, encoded as letters. Windows preserves that order and
never recomputes it, so removing a dead handler without fixing `MRUList`
leaves a dangling reference that Windows will not clean up on its own.

The repair removes the dead handler values and rewrites `MRUList` in the same
pass, dropping exactly the letters whose values were removed and preserving
the recency order of the survivors. Sparse letter sequences are normal and are
left alone; only genuinely dangling references are treated as corruption.

```powershell
# Preview both the removals and the MRUList rewrite
.\src\ftype-audit.ps1 -Path .txt -DryRun

# Apply, and stop before mutating if the backup cannot be verified
.\src\ftype-audit.ps1 -Path .txt -Clean -Backup
```

---

## Automation Integration

### Scheduled Audit

```powershell
Register-ScheduledJob -Name "DailyFtypeAudit" -ScriptBlock {
    Import-Module FtypeAudit
    'txt', 'pdf', 'docx' | ForEach-Object {
        $snapshot = Get-AssociationSnapshot -Extension $_
        $diagnosis = Test-AssociationHealth -Snapshot $snapshot
        [pscustomobject]@{
            Extension = $_
            Issues    = $diagnosis.Evidence.Count
            Evidence  = $diagnosis.Evidence
        }
    } | Export-Clixml "\\server\audits\$(Get-Date -Format yyyyMMdd).xml"
} -Trigger (New-JobTrigger -Daily -At 2AM)
```

### Pipeline Use

```powershell
'txt', 'pdf' | ForEach-Object {
    $snapshot = Get-AssociationSnapshot -Extension $_
    $diagnosis = Test-AssociationHealth -Snapshot $snapshot
    if ($diagnosis.Evidence.Count -gt 0) {
        [pscustomobject]@{ Extension = $_; Issues = $diagnosis.Evidence }
    }
}
```

The script wrapper exits with a non-zero code on validation failure, which makes
it usable as a CI gate.

---


* Always verify backups before repair.
* The tool is not code-signed; rely on `-DryRun` and `-Backup` instead.
* Prefer user-scope audits before system-wide changes.
* Do not disable execution policies for convenience.



---

## Troubleshooting

### Access Denied

Run elevated:

```powershell
Start-Process powershell -Verb RunAs
```

### Inspect a Single Handler

When a handler is reported as broken, resolve it directly to see why:

```powershell
Resolve-HandlerTarget -Handler 'chrome.exe'
```

The result distinguishes the failure modes that matter:

| Status | Meaning |
|--------|---------|
| `Resolved` | The shell can launch this handler |
| `NotRegistered` | No application registration exists at all |
| `NotOpenable` | Registered, but with no verb that can open a document |
| `TargetMissing` | Registered, but the target executable was uninstalled |
| `Malformed` | The stored value is not a shape Windows understands |

### Validate a Backup

`.reg` backups can be checked without touching the registry:

```powershell
# Confirm the file is a well-formed registry script
Get-Content .\ftype-backup-20260101-120000.reg -TotalCount 1
# Windows Registry Editor Version 5.00

# Inspect which keys it would restore, without importing it
Select-String -Path .\ftype-backup-20260101-120000.reg -Pattern '^\['
```

Do **not** use `reg.exe import` to validate a backup. Importing writes the
keys back into the live registry, overwriting the current state with the
backup. Use it only to restore deliberately, and only after confirming the
file contains the keys you expect.

### MRU References a Handler That Does Not Exist

This shows up as `CorruptMRUOrder` in the evidence output. It means the
`MRUList` names a letter that has no matching `OpenWithList` value.

Windows does not repair this on its own — restarting Explorer, broadcasting an
association change, or re-opening the file all leave the dangling reference
in place. The repair step fixes it: run `-Clean` and the `MRUList` is
rewritten alongside the handler removal.

```powershell
.\src\ftype-audit.ps1 -Path .txt -Explain    # see the dangling letters
.\src\ftype-audit.ps1 -Path .txt -DryRun     # see the planned rewrite
.\src\ftype-audit.ps1 -Path .txt -Clean -Backup
```


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

See LICENSE for full terms.

