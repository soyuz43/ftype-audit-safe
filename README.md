# 🔍 FtypeAudit — Safe File Association Analyzer

FtypeAudit is a hardened, security-aware PowerShell utility for **auditing**, **explaining**, and **repairing** Windows file association conflicts. It maps the semantic layers of the registry (UserChoice, SystemDefault, MRUList) while enforcing safety-first principles with optional backup and dry-run modes.

---

##  Features

- **Audit file type handlers** using a structured `SafeAssociationProfile` model
- **Safe registry mutation** with dry-run simulation and optional `.reg` backup
- **Explain mode** interprets conflicts in user vs. system behavior
- **Literal mode** gives you raw technical diagnostic data
- **Force mode** enables controlled registry repair (with backup or preview)

---

## 🛠 Usage

### Basic Audit

```powershell
.\ftype-audit.ps1 .json
```


Dry Run (No Changes)
```
.\ftype-audit.ps1 .txt -DryRun
```
Backup Before Repair
```
.\ftype-audit.ps1 .docx -Backup -Force
```
Technical Report
```
.\ftype-audit.ps1 .html -Literal
```
Explanation of Layers
```
.\ftype-audit.ps1 .md -Explain
```
#### Parameters
Parameter	Description
-Path	File or extension to analyze (e.g., .txt, C:\file.pdf)
-DryRun	Preview changes without writing to registry
-Backup	Create .reg backup before making any changes
-BackupPath	Custom path for registry backup file
-Force	Skip confirmation prompt (used with actual registry changes)
-Explain	Display analysis of file association conflicts
-Literal	Output raw technical details only
-Help	Show usage instructions
🧾 Output

Example technical report:

[Technical Analysis: .txt]
----------------------------------------
User Choice ProgID: txtfile
System Default:     txtfile
MRU List Validity:  Valid

Handler Inventory:
  a: NOTEPAD.EXE [OK]
  b: Code.exe     [MISSING]

🔐 Security & Signing

This script supports safe execution in locked-down environments:

    Complies with AllSigned policies if digitally signed

    Use your enterprise code-signing certificate:

$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath .\ftype-audit.ps1 -Certificate $cert

Module Packaging

To install as a reusable module:

    Rename script to FtypeAudit.psm1

    Create a manifest:

New-ModuleManifest -Path .\FtypeAudit.psd1 `
    -RootModule 'FtypeAudit.psm1' `
    -FunctionsToExport '*' `
    -Author 'Your Name' `
    -Description 'Safe file association analyzer and repair tool'

    Import as needed:

Import-Module .\FtypeAudit.psd1

