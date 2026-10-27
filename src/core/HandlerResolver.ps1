# src\core\HandlerResolver.ps1
# Resolves OpenWithList handler entries the way the Windows shell actually does.
#
# The previous implementation used only Test-Path and Get-Command, neither of
# which is part of the shell's lookup chain. That produced false "broken"
# verdicts for live applications (chrome.exe, Code.exe, firefox.exe, VSCodium.exe
# and UWP handlers such as Notepad), causing the repair step to delete working
# associations that Explorer then re-created.
#
# The lookup order below mirrors the shell's real resolution order:
#
#   1. App Paths\        (HKLM then HKCU) - bare exe names ("chrome.exe")
#   2. Applications\     (HKCU then HKLM) - bare exe names with a shell verb
#   3. ProgID            (HKEY_CLASSES_ROOT) - "VSCodium.json", "txtfilelegacy"
#   4. AppX package      - "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App" (AUMID)
#   5. Direct path       - an absolute path to an existing file
#
# Note: the "HKCR:" PSDrive is not mounted in PowerShell 7 on this platform, so
# every Test-Path "HKCR:\..." call silently returned $false. The merged view is
# reached through the "Registry::HKEY_CLASSES_ROOT" provider path instead.

# --- Resolution outcome ---------------------------------------------------

# Why a handler could not be resolved. These are deliberately distinct so the
# report can tell the user *why* something is dead rather than just that it is.
enum HandlerResolution {
    Resolved
    NotRegistered        # no application registration anywhere
    NotOpenable          # registered, but with no verb that can open a file
    TargetMissing        # registered, but the target executable is gone
    Malformed            # value is not a shape Windows understands
}

class HandlerResolutionResult {
    [string]$Handler
    [HandlerResolution]$Status
    [string]$ResolvedPath
    [string]$Method
    [string]$Detail

    HandlerResolutionResult([string]$handler, [HandlerResolution]$status, [string]$resolvedPath, [string]$method, [string]$detail) {
        $this.Handler      = $handler
        $this.Status       = $status
        $this.ResolvedPath = $resolvedPath
        $this.Method       = $method
        $this.Detail       = $detail
    }

    [bool] IsResolved() {
        return ($this.Status -eq [HandlerResolution]::Resolved)
    }
}

# --- Internal helpers -----------------------------------------------------

# Strips a surrounding pair of double quotes and returns the bare executable
# name plus any trailing arguments. Windows stores some OpenWithList values as
# a full command line (e.g. '"C:\path\app.exe" -arg "%1"').
function Split-HandlerCommand {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Handler)

    $trimmed = $Handler.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return [pscustomobject]@{ Executable = ''; Arguments = '' }
    }

    # Quoted form: "C:\path\app.exe" -arg "%1"
    if ($trimmed -match '^"(?<exe>[^"]+)"(?<rest>.*)$') {
        return [pscustomobject]@{ Executable = $Matches.exe; Arguments = $Matches.rest.Trim() }
    }

    # Unquoted with arguments: C:\path\app.exe -arg
    #
    # Only treat the value as a command line when it actually looks like one.
    # A bare name may legitimately contain spaces ('LM Studio.exe',
    # 'SD Prompt Reader.exe') and is a ProgID, not an executable plus
    # arguments. Splitting on the first space would look up 'LM' and
    # wrongly report the handler as unregistered.
    if ($trimmed -match '\\') {
        $space = $trimmed.IndexOf(' ')
        if ($space -gt 0) {
            return [pscustomobject]@{ Executable = $trimmed.Substring(0, $space); Arguments = $trimmed.Substring($space + 1) }
        }
    }

    return [pscustomobject]@{ Executable = $trimmed; Arguments = '' }
}

# Extracts the executable path from a shell verb command line, dropping the
# %1 placeholder and any switches.
function Get-ExecutableFromCommand {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) {
        return $null
    }

    $trimmed = $Command.Trim()
    if ($trimmed -match '^"(?<exe>[^"]+)"') {
        return $Matches.exe
    }

    # Unquoted: strip the %1 placeholder first, then take the leading path.
    $withoutPlaceholder = $trimmed -replace '\s*%1\s*$', ''
    if ($withoutPlaceholder -match '^(?<exe>.+?\.exe)(\s|$)') {
        return $Matches.exe
    }

    return $null
}

# Reads a shell verb command from a registry key without throwing.
function Get-ShellOpenCommand {
    param([Parameter(Mandatory)][string]$KeyPath)

    try {
        $key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
        $command = $key.GetValue('')
        if ($command) {
            return $command
        }
    }
    catch {
        # Missing key or access denied - treat as "not registered here".
    }
    return $null
}

# --- Resolution steps -----------------------------------------------------

# Step 1: App Paths\ - how Windows locates a bare executable name.
function Resolve-ViaAppPath {
    param([Parameter(Mandatory)][string]$Executable)

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
    )

    foreach ($root in $roots) {
        $keyPath = Join-Path $root $Executable
        try {
            $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
            $target = $key.GetValue('')
            if ($target) {
                if (Test-Path -LiteralPath $target) {
                    return [pscustomobject]@{ Path = $target; Detail = "App Paths\$Executable ($root)" }
                }
                return [pscustomobject]@{ Path = $null; Detail = "App Paths\$Executable points at a missing file: $target" }
            }
        }
        catch {
            # Not registered under this root.
        }
    }
    return $null
}

# Step 2: Applications\ - an application registration with a shell verb.
function Resolve-ViaApplicationRegistration {
    param([Parameter(Mandatory)][string]$Executable)

    $roots = @(
        'HKCU:\Software\Classes\Applications',
        'HKLM:\SOFTWARE\Classes\Applications'
    )

    foreach ($root in $roots) {
        $keyPath = Join-Path $root $Executable
        $command = Get-ShellOpenCommand -KeyPath (Join-Path $keyPath 'shell\open\command')
        if (-not $command) {
            continue
        }

        $exePath = Get-ExecutableFromCommand -Command $command
        if (-not $exePath) {
            continue
        }

        if (Test-Path -LiteralPath $exePath) {
            return [pscustomobject]@{ Path = $exePath; Detail = "Applications\$Executable ($root)" }
        }
        return [pscustomobject]@{ Path = $null; Detail = "Applications\$Executable points at a missing file: $exePath" }
    }
    return $null
}

# Step 3: ProgID - a class registration under HKEY_CLASSES_ROOT.
function Resolve-ViaProgId {
    param([Parameter(Mandatory)][string]$ProgId)

    $keyPath = "Registry::HKEY_CLASSES_ROOT\$ProgId"
    if (-not (Test-Path -LiteralPath $keyPath)) {
        return $null
    }

    $command = Get-ShellOpenCommand -KeyPath (Join-Path $keyPath 'shell\open\command')
    if ($command) {
        $exePath = Get-ExecutableFromCommand -Command $command
        if ($exePath -and (Test-Path -LiteralPath $exePath)) {
            return [pscustomobject]@{ Path = $exePath; Detail = "ProgID $ProgId" }
        }
        if ($exePath) {
            return [pscustomobject]@{ Path = $null; Detail = "ProgID $ProgId points at a missing file: $exePath" }
        }
    }

    # A registered class with no 'open' verb. Windows can still launch it for
    # some verbs (printto, edit, explore), but it cannot open a document.
    # The previous implementation reported these as dead, which was wrong:
    # the registration exists and is still usable for its intended verb.
    $shellPath = Join-Path $keyPath 'shell'
    $verbs = @()
    try {
        $verbs = (Get-ChildItem -LiteralPath $shellPath -ErrorAction Stop).PSChildName
    }
    catch {
        $verbs = @()
    }

    if ($verbs.Count -gt 0) {
        return [pscustomobject]@{
            Path   = $null
            Detail = "ProgID $ProgId is registered (verbs: $($verbs -join ', ')) but has no 'open' verb"
        }
    }

    return [pscustomobject]@{ Path = $null; Detail = "ProgID $ProgId is registered but exposes no shell verbs" }
}

# Step 4: AppX package - the "PackageFamily!ApplicationId" form used by
# Microsoft Store apps in OpenWithList.
function Resolve-ViaAppXPackage {
    param([Parameter(Mandatory)][string]$Aumid)

    if ($Aumid -notmatch '!') {
        return $null
    }

    $family = $Aumid.Split('!')[0]
    if (-not $family) {
        return $null
    }

    try {
        $package = Get-AppxPackage -ErrorAction Stop |
            Where-Object { $_.PackageFamilyName -eq $family } |
            Select-Object -First 1
    }
    catch {
        return $null
    }

    if (-not $package) {
        return [pscustomobject]@{ Path = $null; Detail = "AppX package '$family' is not installed" }
    }

    # Confirm the specific application id exists in the package manifest.
    $appId = $Aumid.Split('!', 2)[1]
    try {
        $manifestIds = ($package | Get-AppxPackageManifest -ErrorAction Stop).
            Package.Applications.Application.Id
    }
    catch {
        $manifestIds = @()
    }

    if ($manifestIds -and ($appId -notin $manifestIds)) {
        return [pscustomobject]@{ Path = $null; Detail = "AppX package '$family' is installed but does not expose application '$appId'" }
    }

    return [pscustomobject]@{
        Path   = $package.InstallLocation
        Detail = "AppX package $Aumid"
    }
}

# --- Public entry point ---------------------------------------------------

<#
.SYNOPSIS
Resolves a single OpenWithList handler value to the target the shell would launch.

.DESCRIPTION
Attempts each resolution method in the shell's own order and returns the first
that succeeds. When resolution fails the result explains why, so the caller can
distinguish "never registered" from "registered but the program was uninstalled".

.PARAMETER Handler
The raw OpenWithList value, e.g. 'chrome.exe', 'VSCodium.json',
'Microsoft.WindowsNotepad_8wekyb3d8bbwe!App' or 'aebdc'.

.OUTPUTS
HandlerResolutionResult
#>
function Resolve-HandlerTarget {
    [CmdletBinding()]
    [OutputType([HandlerResolutionResult])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Handler
    )

    $trimmed = $Handler.Trim()

    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return [HandlerResolutionResult]::new(
            $Handler,
            [HandlerResolution]::Malformed,
            $null,
            'None',
            'Handler value is empty'
        )
    }

    $parsed = Split-HandlerCommand -Handler $trimmed
    $executable = $parsed.Executable

    # A quoted or spaced value is a full command line. Resolve the executable
    # portion directly against the file system.
    if ($executable -match '\\') {
        if (Test-Path -LiteralPath $executable) {
            return [HandlerResolutionResult]::new(
                $Handler, [HandlerResolution]::Resolved, $executable, 'DirectPath', $executable
            )
        }
        return [HandlerResolutionResult]::new(
            $Handler, [HandlerResolution]::TargetMissing, $null, 'DirectPath',
            "Referenced file does not exist: $executable"
        )
    }

    # An AppX AUMID is resolved before the generic ProgID lookup, because the
    # AUMID form is not itself a registered class key.
    if ($trimmed -match '!') {
        $appx = Resolve-ViaAppXPackage -Aumid $trimmed
        if ($appx) {
            if ($appx.Path) {
                return [HandlerResolutionResult]::new(
                    $Handler, [HandlerResolution]::Resolved, $appx.Path, 'AppXPackage', $appx.Detail
                )
            }
            return [HandlerResolutionResult]::new(
                $Handler, [HandlerResolution]::TargetMissing, $null, 'AppXPackage', $appx.Detail
            )
        }
    }

    # Bare executable names: App Paths, then Applications.
    if ($executable -match '\.exe$') {
        $appPath = Resolve-ViaAppPath -Executable $executable
        if ($appPath) {
            if ($appPath.Path) {
                return [HandlerResolutionResult]::new(
                    $Handler, [HandlerResolution]::Resolved, $appPath.Path, 'AppPath', $appPath.Detail
                )
            }
            return [HandlerResolutionResult]::new(
                $Handler, [HandlerResolution]::TargetMissing, $null, 'AppPath', $appPath.Detail
            )
        }

        $application = Resolve-ViaApplicationRegistration -Executable $executable
        if ($application) {
            if ($application.Path) {
                return [HandlerResolutionResult]::new(
                    $Handler, [HandlerResolution]::Resolved, $application.Path, 'Application', $application.Detail
                )
            }
            return [HandlerResolutionResult]::new(
                $Handler, [HandlerResolution]::TargetMissing, $null, 'Application', $application.Detail
            )
        }

        return [HandlerResolutionResult]::new(
            $Handler, [HandlerResolution]::NotRegistered, $null, 'None',
            "No application registration found for '$executable'"
        )
    }

    # Anything else is treated as a ProgID.
    $progId = Resolve-ViaProgId -ProgId $executable
    if ($progId) {
        if ($progId.Path) {
            return [HandlerResolutionResult]::new(
                $Handler, [HandlerResolution]::Resolved, $progId.Path, 'ProgId', $progId.Detail
            )
        }

        $status = if ($progId.Detail -match "no 'open' verb|no shell verbs") {
            [HandlerResolution]::NotOpenable
        }
        else {
            [HandlerResolution]::TargetMissing
        }

        return [HandlerResolutionResult]::new(
            $Handler, $status, $null, 'ProgId', $progId.Detail
        )
    }

    return [HandlerResolutionResult]::new(
        $Handler, [HandlerResolution]::NotRegistered, $null, 'None',
        "No ProgID registration found for '$executable'"
    )
}

<#
.SYNOPSIS
Resolves every handler in an OpenWithList snapshot.

.DESCRIPTION
Takes an AssociationSnapshot and returns one HandlerResolutionResult per
OpenWithList entry, keyed by the registry value name ('a', 'b', ...).

.PARAMETER Snapshot
The snapshot whose OpenWithList values should be resolved.
#>
function Resolve-OpenWithListHandlers {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, HandlerResolutionResult]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [AssociationSnapshot]$Snapshot
    )

    $results = [System.Collections.Generic.Dictionary[string, HandlerResolutionResult]]::new()

    $openWithList = $Snapshot.RegistryValues.OpenWithList
    if (-not $openWithList) {
        return $results
    }

    foreach ($property in $openWithList.psobject.Properties) {
        if ($property.Name -notmatch '^[a-z]$') {
            continue
        }

        $value = [string]$property.Value
        $results[$property.Name] = Resolve-HandlerTarget -Handler $value
    }

    return $results
}

