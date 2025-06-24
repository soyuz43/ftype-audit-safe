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

| Parameter   | Description                                                   |
|-------------|---------------------------------------------------------------|
| `-Path`     | File or extension to analyze (e.g., `.txt`, `C:\file.pdf`)    |
| `-DryRun`   | Preview changes without writing to registry                   |
| `-Backup`   | Create `.reg` backup before making any changes                |
| `-BackupPath` | Custom path for registry backup file                        |
| `-Force`    | Skip confirmation prompt (used with actual registry changes)  |
| `-Explain`  | Display analysis of file association conflicts                |
| `-Literal`  | Output raw technical details only                             |
| `-Help`     | Show usage instructions                                       |

#### 🧾 **Example Output**

When analyzing a file association using the `-Explain` flag, you'll see a human-readable summary:

```plaintext
[EXPLAINED VIEW: .TXT]
Timestamp: 2025-06-24 12:45

CORE STATUS:
[+] Configuration Valid

REGISTRY ANALYSIS:
User Choice:    txtfile
System Default: txtfile
Valid Handlers: 1
MRU Integrity:  Intact
````

For raw technical data, use the `-Literal` flag:

```plaintext
Association Health Report: .txt
Captured at: 2025-06-24 12:45:21

[Evidence]
  @{State=BrokenHandlerPath; Message=Handler resolution failed: Code.exe}
  @{State=CorruptMRUOrder; Message=MRU references invalid handlers: a,e,b}
```

To preview repairs without modifying the registry, use `-DryRun`:

```plaintext
.txt    : [+]
[>] Simulated repair operations:
    would fix: @{State=BrokenHandlerPath; Message=Handler resolution failed: Code.exe}
    would fix: @{State=CorruptMRUOrder; Message=MRU references invalid handlers: a,e,b}
```
> 🛑 Use `-Clean` to apply changes. Elevation required.

Note: `-Dry-Run` flags MRU entries as they exist in the registry, whereas `-Explain` shows MRU integrity after resolving only valid handlers—so a corrupt raw MRU can appear fixed once invalid handlers are filtered out._





#### 🔐 Security & Signing

This script supports safe execution in locked-down environments:

    Complies with AllSigned policies if digitally signed

    Use your enterprise code-signing certificate:
```
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath .\ftype-audit.ps1 -Certificate $cert
```
#### Module Packaging

To install as a reusable module:

- Rename script to `FtypeAudit.psm1`

    + Create a manifest:
```
New-ModuleManifest -Path .\FtypeAudit.psd1 `
    -RootModule 'FtypeAudit.psm1' `
    -FunctionsToExport '*' `
    -Author 'Your Name' `
    -Description 'Safe file association analyzer and repair tool'
```
- Import as needed:
```
Import-Module .\FtypeAudit.psd1
```
