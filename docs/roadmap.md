1. **JSON-Structured Output** - *Done*

   * `-Json` emits a versioned document containing the snapshot, the
     diagnosis, the per-handler resolution results, and the repair plan.
     `-OutputPath` writes it to a file. The flag is named `-Json` rather than
     `-LiteralJson`, since `-Literal` already means "raw technical output" in
     this tool and the two would have been confusingly similar.

2. **System-Level Association Support**

   * Extend your snapshot logic to also check (and optionally repair) HKLM associations (e.g. under `Registry::HKEY_CLASSES_ROOT`) so corporate or machine-wide defaults are covered, not just user-level keys.
   * Note: the merged `HKEY_CLASSES_ROOT` view is read via
     `Registry::HKEY_CLASSES_ROOT\...`. The `HKCR:` PSDrive is not mounted in
     PowerShell 7, and is absent in Windows PowerShell 5.1 on this machine.

3. **“Clean” Interactive Preview**

   * Offer an interactive mode (`-WhatIfInteractive`) where, after a dry-run, you prompt the user to confirm each individual fix before applying it.

4. **Logging and Transcripts**

   * Wire in `Start-Transcript`/`Stop-Transcript` or a dedicated logging module so users can capture full audit runs to a file for later review.

5. **Module Packaging & CI**

   * Convert the scripts into a proper PowerShell module with a `.psd1` manifest, publish to the PowerShell Gallery, and set up a GitHub Actions CI workflow that runs your Pester tests on every push.

6. **Expand Test Coverage**

   * Add Pester tests for:

     * Reading the default value via `.GetValue('')`
     * Snapshots with no registry keys present
     * Populating and validating `HandlerPaths` entries
     * Simulated clean vs. actual clean

7. **Error Handling & Reporting** - *Partially done*

    * The exit code contract now distinguishes a failed audit from a finding,
      and separates validation failure, registry access failure, unsupported
      environment, and operation failure. See the exit code table in
      `docs/index.md`.

    * Still to do: surface the individual registry errors (access denied vs.
      key missing) inside the JSON document, rather than only as a combined
      failure count.

8. **Bulk / File-Path Mode** - *Done*

    * `-Path` accepts a comma-separated list of extensions (e.g.
      `-Path .txt,.md`) and audits each in one pass. An entry that cannot be
      validated is reported and skipped rather than aborting the run. A
      single file path was already supported and still is.

    * The exit code contract now distinguishes a failed audit from a finding,
      and `-FailOnIssues` promotes a finding into a process failure for CI
      gating.

9. **Localization / Internationalization**

   * Abstract all output strings into a resource file so you can add translations later (e.g. Spanish, German).

10. **Telemetry-Ready Hooks**

    * Add an opt-in “report usage” endpoint or log hook so you can collect anonymous stats on which extensions are most commonly audited/cleaned.

11. **Backup Verification** — *Done*

    * `Backup-RegistryState` now checks the reg.exe exit code, that the file
      exists and is non-empty, and that it parses as a registry script before
      reporting success. A failed backup aborts the cleanup unless
      `-AllowBackupFailure` is passed explicitly.

12. **Enhance Documentation**

    * Add a “Troubleshooting” section covering common failures (e.g. UWP ProgID quirks) and register a help file (`.xml`) so `Get-Help ftype-audit` works out of the box.

