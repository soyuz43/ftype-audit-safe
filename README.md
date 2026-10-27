# 🔍 FtypeAudit — Safe File Association Analyzer

FtypeAudit is a hardened, security-aware PowerShell utility for **auditing**, **explaining**, and **repairing** Windows file association conflicts. It maps the semantic layers of the registry (UserChoice, SystemDefault, MRUList) while enforcing safety-first principles with optional backup and dry-run modes.

---

##  Features

- **Audit file type handlers** using a structured `AssociationSnapshot` model
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
.\ftype-audit.ps1 .docx -Backup -Clean
```
Technical Report
```
.\ftype-audit.ps1 .html -Literal
```
Explanation of Layers
```
.\ftype-audit.ps1 .html -Explain
```
#### Parameters

| Parameter           | Description                                                   |
|---------------------|---------------------------------------------------------------|
| `-Path`             | File or extension to analyze (e.g., `.txt`, `C:\file.pdf`)    |
| `-DryRun`           | Preview changes without writing to registry                   |
| `-Backup`           | Create `.reg` backup before making any changes                |
| `-BackupPath`       | Custom path for registry backup file                        |
| `-Clean`            | Perform safe cleanup of file association entries              |
| `-SkipConfirmation` | Skip interactive confirmation prompts (affects -Clean, -DryRun)|
| `-AllowBackupFailure` | Continue the cleanup even when the registry backup failed. Off by default; a failed backup aborts the cleanup. |
| `-Explain`          | Display analysis of file association conflicts                |
| `-Literal`          | Output raw technical details only                             |
| `-IsExtension`      | Treat input Path explicitly as an extension (bypass file-exists check) |
| `-AuditPython`      | Run Python residue audit and exit                             |
| `-Help`             | Show detailed help screen                                       |

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
  BrokenHandlerPath: Handler resolution failed: aebdc (No ProgID registration found for 'aebdc')
  CorruptMRUOrder: MRU references invalid handlers: b
```

To preview repairs without modifying the registry, use `-DryRun`:

```plaintext
.txt    : [!] 2 issue(s)

Legend:
  [+]  All association checks passed successfully.
  [!]  One or more issues detected — run with -Explain for details.
[>] Simulated repair operations for extension '.txt':
    would remove handler key: b
    would rewrite MRUList: 'afgbcde' -> 'afgcde'
```
> 🛑 Use `-Clean` to apply changes. Elevation required.

Note: `-DryRun` flags MRU entries as they exist in the registry, whereas `-Explain` shows MRU integrity after resolving only valid handlers—so a corrupt raw MRU can appear fixed once invalid handlers are filtered out.

#### 🔁 MRUList Repair

The `OpenWithList` key carries an `MRUList` value — the handlers in
most-recently-used order, encoded as letters. Windows never recomputes it, so
removing a dead handler without fixing `MRUList` leaves a letter pointing at a
value that no longer exists. The extension stays broken and the tool can never
report it as clean.

The repair does both in one pass:

1. Removes only the handler values whose targets could not be resolved.
2. Rewrites `MRUList`, dropping exactly the letters whose values were removed
   and preserving the recency order of the survivors.
3. Removes the `MRUList` value entirely if every letter it referenced was
   deleted.

Gaps in the letter sequence are normal — Windows writes `MRUList` over a sparse
set of keys — and are preserved. Only genuinely dangling references are
treated as corruption.

Run the same repair twice and the second run is a no-op: the tool reports the
extension as valid with `MRU Integrity: Intact`.





#### 🔐 Security & Signing

This tool is **not** digitally signed. That is a deliberate choice, not an
oversight:

- Signing it would mean re-signing after every edit, since any change
  invalidates the Authenticode hash.
- A self-signed certificate trusted as a root would let *anyone* produce
  scripts that appear to come from this project. That is a downgrade in
  security, not an upgrade.

The tool's safety comes from its behaviour rather than its signature:

- Registry writes only happen under `-Clean`, never during an audit.
- `-DryRun` previews every change without touching the registry.
- `-Backup` writes a `.reg` snapshot of the affected key before any mutation.
- A failed backup **aborts** the cleanup. `-SkipConfirmation` only suppresses
  the prompt — it does not weaken backup protection. Bypassing the abort is
  a separate, explicit opt-in via `-AllowBackupFailure`.
- Reads are unprivileged and require no elevation.

#### 🔁 What a Repair Actually Changes

Removing a dead handler is only half the job. The `OpenWithList` key also
holds an `MRUList` value — a string of letters naming the handlers in
most-recently-used order. Windows never recomputes it, so deleting a handler
without fixing `MRUList` leaves a letter pointing at a value that no longer
exists. The extension stays broken, and the tool can never report it as clean.

The repair therefore does both in one pass:

1. Removes only the handler values whose targets could not be resolved.
2. Rewrites `MRUList` by dropping exactly the letters whose values were
   removed, preserving the recency order of the survivors.
3. Removes the `MRUList` value entirely if every letter it referenced was
   deleted.

Gaps in the letter sequence are normal and are preserved — Windows writes
`MRUList` over a sparse set of keys. Only genuinely dangling references are
treated as corruption.

Run the same repair twice and the second run is a no-op: the tool reports the
extension as valid with `MRU Integrity: Intact`.

If you need to run under an `AllSigned` execution policy, sign it yourself with
a certificate your organisation already trusts:

```powershell
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath .\src\ftype-audit.ps1 -Certificate $cert
```

Note that `Set-AuthenticodeSignature` must be re-run after every subsequent
edit, otherwise the signature becomes invalid and the file reports as
`NotSigned`.

#### Module Packaging

The module layout is already in place under `src/`:

```
src/
  FtypeAudit.psd1        module manifest
  FtypeAudit.psm1        module entry point
  core/                  snapshot, resolver, diagnosis, reporter, repair
  platform/              elevation and environment detection
  cleanup/               Python residue audit
```

To use it as a module:

```powershell
Import-Module .\src\FtypeAudit.psd1

Get-AssociationSnapshot -Extension '.txt'
Resolve-HandlerTarget -Handler 'chrome.exe'
Test-AssociationHealth -Snapshot (Get-AssociationSnapshot -Extension '.txt')
```

Exported functions:

| Function | Purpose |
|----------|---------|
| `Get-AssociationSnapshot` | Capture the current registry state for an extension |
| `Resolve-HandlerTarget` | Resolve a single handler the way the shell would |
| `Test-AssociationHealth` | Diagnose the captured state |
| `Write-AssociationReport` | Render a snapshot and diagnosis in Literal/Explain/Summary modes |
| `Invoke-SafeClean` | Remove dead handlers, with dry-run and backup support |
