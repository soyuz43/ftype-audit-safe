# 📘 FtypeAudit Documentation

**Secure File Association Management for Windows**  
*Version 1.0.0 | MIT License*

---

##  Overview

FtypeAudit is a PowerShell-based toolkit for:
- 🔍 **Analyzing** file type associations
- 🧹 **Cleaning** invalid registry entries
Built with safety-first principles and enterprise-grade auditing capabilities.

---

## 🛠 Installation

### Method 1: Script Deployment
```powershell
# Download and run directly
irm https://ftypeaudit.example.com/latest.ps1 | iex
```

### Method 2: Module Installation
```powershell
# Install from PowerShell Gallery
Install-Module -Name FtypeAudit -Scope CurrentUser

# Manual module placement
Copy-Item -Path .\FtypeAudit -Destination $env:PSModulePath -Recurse
```

**Requirements**:
- PowerShell 5.1+ (Windows 10/11, Server 2016+)
- Execution Policy: `RemoteSigned`
- Admin Rights: Recommended for system-wide analysis

---

## 🔥 Core Features

| Feature | Description | Safety Level |
|---------|-------------|--------------|
| `Elevation Guard` | Warns when running unprivileged | ⚠️ Advisory |
| `Dry-Run Mode` | Preview changes without execution | 🛡️ Protected |
| `Registry Backup` | Automatic .REG file snapshots | 🔄 Reversible |
| `Signature Validation` | Verify script integrity via PGP | 🔐 Trusted |
| `MRU Forensics` | Detect historical handler drift | 🔍 Investigative |

---

## 🖥 Basic Usage

### 1. Analyze Associations
```powershell
# Single extension analysis
Get-FileAssociation -Extension .pdf -Verbose

# Full system scan
Invoke-FullAssociationAudit -OutputFormat JSON
```

### 2. Cleanup Workflow
```powershell
# Safe removal of invalid entries
Clear-AssociationArtifacts -Extension .docx -BackupPath ~/backups

# Force repair with confirmation
Repair-FileHandlers -Extension .ps1 -Force -Confirm:$false
```

### 3. System Integration
```powershell
# Export settings for compliance
Export-AssociationPolicy -Path .\policy.json

# Import organizational standards
Import-AssociationPolicy -Path .\enterprise_rules.json
```

---

## 📋 Command Reference

### Primary Commands

| Command | Parameters | Output |
|---------|------------|--------|
| `Get-FileAssociation` | `-Extension`, `-Depth` | Object |
| `Clear-AssociationArtifacts` | `-Backup`, `-Force` | Log |
| `Compare-AssociationProfiles` | `-Source`, `-Target` | Diff |

### Common Options

| Flag | Purpose |
|------|---------|
| `-WhatIf` | Simulation mode |
| `-Historical` | Show 30-day changes |
| `-DigitalSignature` | Verify code signature |

---

## 🚨 Security

### Critical Considerations
1. **Registry Edits**: Always validate backups
   ```powershell
   New-RegistryCheckpoint -Name "PreAudit"
   ```
2. **Signature Verification**
   ```powershell
   Get-AuthenticodeSignature .\FtypeAudit.ps1 | Verify-Signature
   ```
3. **Least Privilege**  
   Run user-level audits first:
   ```powershell
   Invoke-UserScopeAnalysis -CurrentUser
   ```

<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({ startOnLoad: true });</script>

<div class="mermaid">
graph LR
A[Start Audit] --> B{Admin Needed?}
B -->|No| C[User-Level Scan]
B -->|Yes| D[Elevated Session]
C --> E[Review Findings]
D --> E
E --> F{Changes Required?}
F -->|Yes| G[Backup → Dry-Run → Apply]
F -->|No| H[Generate Report]
</div>

---

## 🧩 Advanced Scenarios

### 1. Pipeline Integration
```powershell
# Bulk handler repair
Get-ChildItem *.log | ForEach-Object {
    Get-FileAssociation $_.Extension |
    Repair-FileHandlers -Policy Strict
}
```

### 2. Enterprise Automation
```powershell
# Scheduled audit task
Register-ScheduledJob -Name "DailyFtypeCheck" -ScriptBlock {
    Import-Module FtypeAudit
    Invoke-FullAssociationAudit |
    Export-Clixml "\\server\audits\$(Get-Date -Format yyyyMMdd).xml"
} -Trigger (New-JobTrigger -Daily -At 2AM)
```

### 3. Forensic Analysis
```powershell
# Compare user vs system defaults
$user = Get-FileAssociation .pdf -Scope CurrentUser
$system = Get-FileAssociation .pdf -Scope AllUsers
Compare-AssociationProfiles -Reference $user -Difference $system
```

---

## 🚑 Troubleshooting

### Common Issues

| Symptom | Solution |
|---------|----------|
| Access Denied | Run as Admin → `Start-Process powershell -Verb RunAs` |
| Missing Handlers | `Restore-DefaultHandlers -Extension .xlsx` |
| Ghost Entries | `Clear-AssociationArtifacts -Force -Backup` |

### Diagnostic Commands
```powershell
# Registry health check
Test-AssociationStore -Scope AllUsers

# Handler resolution test
Resolve-FileHandler -Path example.rtf -Simulate
```

---

## ❓ FAQ

**Q: How to handle UWP app associations?**  
A: Use `Get-AppxHandlers` for modern apps:
```powershell
Get-AppxHandlers -Package *Microsoft.Paint*
```

**Q: Why can't I modify certain associations?**  
A: Some system-protected types require Group Policy overrides.

**Q: Cross-user association management?**  
A: Use `-Scope` parameter:
```powershell
Get-FileAssociation .mp3 -Scope AllUsers
```

---

## 📜 License

```text
MIT License
Copyright (c) 2024 William Stetar

Permission is hereby granted... (standard MIT terms)
```

*For full license text, see [LICENSE.md](https://github.com/soyuz43/ftype-audit-safe/blob/main/LICENSE)*

---

**Need Help?**  
[Open an Issue](https://github.com/soyuz43/ftype-audit-safe/issues) | 