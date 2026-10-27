# src\core\MruList.ps1
# Maintains the MRUList value of an OpenWithList key.
#
# Background
# ----------
# The MRUList value is a string of letters, each one naming an OpenWithList
# value ('a'..'z'). It encodes which handler was used most recently, in
# order. Windows does NOT recompute it: it preserves whatever ordering is
# there and only prepends handlers that are newly used.
#
# Two properties follow from that, and both were confirmed against live
# registry data:
#
#   * Gaps are normal. On this machine .jpg has OpenWithList keys
#     a,b,c,d,e,f,g,i,k,h,j with MRUList 'aecdb' - the MRU names five of
#     ten keys and skips the rest. Letters in the list are not required to be
#     contiguous.
#
#   * A letter in MRUList with no matching value is corruption. Windows
#     leaves it alone indefinitely, so the association stays broken until
#     something rewrites it.
#
# The original repair step removed dead OpenWithList values but never
# touched MRUList, so it produced exactly that corruption and could then
# never report the extension as clean.

# Builds the corrected MRUList for a set of surviving handler keys.
<#
.SYNOPSIS
Computes the MRUList value after a set of handler keys has been removed.

.DESCRIPTION
Takes the current MRUList and the set of keys that were removed, and returns
the MRUList with the removed letters filtered out.

The relative order of the surviving letters is preserved. That order is
recency, not key order, so it must not be re-sorted.

If no letters survive, an empty string is returned, which removes the
dangling reference entirely.

.PARAMETER CurrentMruList
The MRUList value as it exists now. May be null or empty.

.PARAMETER RemovedKeys
The OpenWithList value names that were deleted.
#>
function Get-CorrectedMruList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()][AllowEmptyString()]
        [string]$CurrentMruList,

        [Parameter()][AllowEmptyCollection()]
        [string[]]$RemovedKeys = @()
    )

    if ([string]::IsNullOrWhiteSpace($CurrentMruList)) {
        return ''
    }

    $removed = @{}
    foreach ($key in $RemovedKeys) {
        if ($key) {
            $removed[$key] = $true
        }
    }

    $survivors = @()
    foreach ($letter in $CurrentMruList.ToCharArray()) {
        $name = $letter.ToString()
        if ($removed.ContainsKey($name)) {
            continue
        }
        if ($survivors -notcontains $name) {
            $survivors += $name
        }
    }

    return ($survivors -join '')
}

<#
.SYNOPSIS
Writes a corrected MRUList back to an OpenWithList key.

.DESCRIPTION
Filters the MRUList against the handler keys that were removed and writes
the result back. If no letters survive, the MRUList value is removed
entirely rather than being left as an empty string, because an empty value
still shows up as a malformed entry to anything reading the key.

.PARAMETER OpenWithPath
The full registry path to the OpenWithList key.

.PARAMETER CurrentMruList
The MRUList value as it exists now.

.PARAMETER RemovedKeys
The OpenWithList value names that were deleted.
#>
function Update-MruList {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$OpenWithPath,

        [Parameter()][AllowNull()][AllowEmptyString()]
        [string]$CurrentMruList = '',

        [Parameter()][AllowEmptyCollection()]
        [string[]]$RemovedKeys = @()
    )

    $corrected = Get-CorrectedMruList -CurrentMruList $CurrentMruList -RemovedKeys $RemovedKeys

    if ($corrected -eq $CurrentMruList) {
        Write-Verbose "[>] MRUList already consistent with surviving handlers."
        return $corrected
    }

    if (-not $PSCmdlet.ShouldProcess($OpenWithPath, "Rewrite MRUList to '$corrected'")) {
        return $corrected
    }

    if ([string]::IsNullOrEmpty($corrected)) {
        # Every letter referred to a handler we just deleted. Leaving an empty
        # MRUList would keep a malformed entry in the key.
        try {
            Remove-ItemProperty -Path $OpenWithPath -Name 'MRUList' -ErrorAction Stop
            Write-Verbose "[>] Removed MRUList: every referenced handler was deleted."
        }
        catch {
            Write-Error "[!] Failed to remove empty MRUList for '$OpenWithPath': $($_.Exception.Message)"
        }
        return $corrected
    }

    try {
        Set-ItemProperty -Path $OpenWithPath -Name 'MRUList' -Value $corrected -Type String -ErrorAction Stop
        Write-Verbose "[>] Rewrote MRUList to '$corrected'."
    }
    catch {
        Write-Error "[!] Failed to rewrite MRUList for '$OpenWithPath': $($_.Exception.Message)"
    }

    return $corrected
}

<#
.SYNOPSIS
Reports OpenWithList values that MRUList references but that no longer exist.

.DESCRIPTION
A letter in MRUList with no corresponding OpenWithList value is a dangling
reference. These are reported separately from broken handlers because no
handler is involved - the entry is simply orphaned.

.PARAMETER OpenWithPath
The full registry path to the OpenWithList key.
#>
function Get-DanglingMruReference {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$OpenWithPath
    )

    try {
        $key = Get-Item -LiteralPath $OpenWithPath -ErrorAction Stop
    }
    catch {
        return @()
    }

    $mru = $key.GetValue('MRUList')
    if (-not $mru) {
        return @()
    }

    $existing = @($key.GetValueNames())
    $dangling = @()
    foreach ($letter in $mru.ToCharArray()) {
        $name = $letter.ToString()
        if ($existing -notcontains $name) {
            $dangling += $name
        }
    }

    return $dangling
}

<#
.SYNOPSIS
Reads the MRUList that the snapshot was taken from.

.DESCRIPTION
The repair step must rewrite the same MRUList it diagnosed, otherwise the
letters it drops and the letters it removes can disagree. The snapshot is
therefore the primary source.

The registry is only consulted when the snapshot carries no MRUList at all
(for example when a caller builds a snapshot by hand), which keeps the
repair consistent with the diagnosis in the normal case and still usable in
the edge case.

.PARAMETER Map
The AssociationSnapshot being repaired.

.PARAMETER OpenWithPath
Registry path to the OpenWithList key, used only for the fallback read.
#>
function Get-MruListForRepair {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()]
        [object]$Map,

        [Parameter()][AllowEmptyString()]
        [string]$OpenWithPath = ''
    )

    if ($Map) {
        $openWithList = $Map.RegistryValues.OpenWithList
        if ($openWithList) {
            $snapshotMru = $openWithList.MRUList
            if ($snapshotMru) {
                return [string]$snapshotMru
            }
        }
    }

    if ($OpenWithPath) {
        try {
            $mru = (Get-Item -LiteralPath $OpenWithPath -ErrorAction Stop).GetValue('MRUList')
            if ($mru) {
                return [string]$mru
            }
        }
        catch {
            # No MRUList available; nothing to rewrite.
        }
    }

    return ''
}
