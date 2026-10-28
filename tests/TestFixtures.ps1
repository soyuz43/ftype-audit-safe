# tests/TestFixtures.ps1
# Helpers for creating throwaway registry fixtures.
#
# Several tests need an association that is *known* to be broken, or a ProgID
# that is *known* to be registered without an 'open' verb. Reaching for a
# real extension like '.txt' does not work: whether '.txt' has issues depends
# entirely on the machine running the tests. On a clean CI runner it is
# healthy, so a test asserting "issues were found" fails there while passing
# on a developer machine.
#
# These helpers build the exact registry state the test needs, under a
# unique name, and remove it afterwards. HKCU\Software\Classes is merged into
# HKEY_CLASSES_ROOT, so a ProgID created there is visible to the resolver
# exactly as a system-wide registration would be.

function New-TestProgIdWithVerb {
    <#
    .SYNOPSIS
        Registers a ProgID that has a shell verb but no 'open' verb.

    .DESCRIPTION
        Creates HKCU\Software\Classes\<Name>\shell\<Verb>. The resolver
        treats a registered class with verbs but no 'open' verb as
        'NotOpenable' - registered, but unable to open a document.

    .PARAMETER Name
        The ProgID to register. Defaults to a unique generated name.

    .PARAMETER Verb
        The shell verb to create. Defaults to 'printto'.

    .OUTPUTS
        The ProgID name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][string]$Name,
        [Parameter()][string]$Verb = 'printto'
    )

    if (-not $Name) {
        $Name = "FtypeAuditTestProgId$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    }

    $base = "HKCU:\Software\Classes\$Name"
    New-Item -Path (Join-Path $base "shell\$Verb") -Force | Out-Null

    return $Name
}

function New-TestBrokenExtension {
    <#
    .SYNOPSIS
        Creates an extension whose OpenWithList contains a dead handler.

    .DESCRIPTION
        Creates the Explorer FileExts OpenWithList key for a unique extension
        and points one handler at a ProgID that cannot exist. The extension
        is therefore guaranteed to have exactly one broken handler and a
        dangling MRUList reference, regardless of the host machine.

    .PARAMETER Extension
        The extension to create. Defaults to a unique generated name.

    .PARAMETER HandlerKey
        The OpenWithList value name to use. Defaults to 'a'.

    .OUTPUTS
        A hashtable with the Extension, the OpenWithList path, and the
        handler key that was created.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()][string]$Extension,
        [Parameter()][string]$HandlerKey = 'a'
    )

    if (-not $Extension) {
        $Extension = ".ftaudittest$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    }

    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithList"
    New-Item -Path $openWithPath -Force | Out-Null

    # A ProgID that cannot be registered anywhere.
    $deadHandler = "zzzftauditdead$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    New-ItemProperty -Path $openWithPath -Name $HandlerKey -Value $deadHandler -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $openWithPath -Name 'MRUList' -Value $HandlerKey -PropertyType String -Force | Out-Null

    return @{
        Extension     = $Extension
        OpenWithPath  = $openWithPath
        HandlerKey    = $HandlerKey
        HandlerValue  = $deadHandler
    }
}

function Remove-TestFixture {
    <#
    .SYNOPSIS
        Removes registry state created by the fixture helpers.

    .PARAMETER Fixture
        The hashtable returned by New-TestBrokenExtension.

    .PARAMETER ProgId
        A ProgID name returned by New-TestProgIdWithVerb.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][hashtable]$Fixture,
        [Parameter()][AllowNull()][string]$ProgId
    )

    if ($Fixture -and $Fixture.Extension) {
        $fileExts = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Fixture.Extension)"
        Remove-Item -LiteralPath $fileExts -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($ProgId) {
        Remove-Item -LiteralPath "HKCU:\Software\Classes\$ProgId" -Recurse -Force -ErrorAction SilentlyContinue
    }
}
