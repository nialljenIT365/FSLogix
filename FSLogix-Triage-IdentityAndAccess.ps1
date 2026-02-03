#############################################################
# FSLogix AD / Identity Diagnostics (PowerShell 5.1 safe)
# Focus: 0x80070547, 0x80005000, Access denied (5)
#############################################################
Write-Host "Running FSLogix AD / Identity diagnostics..." -ForegroundColor Cyan

# ---- Helpers ----
function Write-Section([string]$title) {
    Write-Host ""
    Write-Host ("==================== {0} ====================" -f $title) -ForegroundColor Cyan
}

function Tail-ContextFromLog {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string[]]$Patterns,
        [int]$ContextBefore = 15,
        [int]$ContextAfter  = 15,
        [int]$MaxMatches    = 5
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host ("[FAIL] Log not found: {0}" -f $Path) -ForegroundColor Red
        return @()
    }

    $hits = Select-String -LiteralPath $Path -Pattern $Patterns -SimpleMatch -ErrorAction SilentlyContinue |
        Select-Object -First $MaxMatches

    if (-not $hits) {
        Write-Host ("[WARN] No matches in: {0}" -f $Path) -ForegroundColor Yellow
        return @()
    }

    $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    $out = @()

    foreach ($h in $hits) {
        $start = [Math]::Max(0, $h.LineNumber - 1 - $ContextBefore)
        $end   = [Math]::Min($lines.Count - 1, $h.LineNumber - 1 + $ContextAfter)

        Write-Host ""
        Write-Host ("[OK]   Match in {0} at line {1}" -f $Path, $h.LineNumber) -ForegroundColor Green
        Write-Host ("------ Context ({0} lines before/after) ------" -f $ContextBefore) -ForegroundColor DarkGray

        for ($i = $start; $i -le $end; $i++) {
            $prefix = ("{0,6}:" -f ($i + 1))
            Write-Host ($prefix + " " + $lines[$i])
        }

        $out += [PSCustomObject]@{
            LogPath     = $Path
            LineNumber  = $h.LineNumber
            MatchLine   = $h.Line.Trim()
            ContextFrom = $start + 1
            ContextTo   = $end + 1
        }
    }

    return $out
}

function Get-LatestLog {
    param(
        [Parameter(Mandatory)] [string]$Folder,
        [Parameter(Mandatory)] [string]$Filter
    )
    Get-ChildItem -LiteralPath $Folder -Filter $Filter -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

# ---- Identify relevant FSLogix logs ----
Write-Section "FSLogix log discovery"

$fslogixRoot = "C:\ProgramData\FSLogix\Logs"
$networkLog  = Get-LatestLog -Folder (Join-Path $fslogixRoot "Network") -Filter "Network-*.log"
$adsLog      = Get-LatestLog -Folder (Join-Path $fslogixRoot "AdsComputerGroup") -Filter "AdsComputerGroup-*.log"
$profileLog  = Get-LatestLog -Folder (Join-Path $fslogixRoot "Profile") -Filter "Profile-*.log"

if ($networkLog) { Write-Host ("[OK]   Latest Network log: {0}" -f $networkLog.FullName) -ForegroundColor Green } else { Write-Host "[WARN] No Network logs found." -ForegroundColor Yellow }
if ($adsLog)     { Write-Host ("[OK]   Latest AdsComputerGroup log: {0}" -f $adsLog.FullName) -ForegroundColor Green } else { Write-Host "[WARN] No AdsComputerGroup logs found." -ForegroundColor Yellow }
if ($profileLog) { Write-Host ("[OK]   Latest Profile log: {0}" -f $profileLog.FullName) -ForegroundColor Green } else { Write-Host "[WARN] No Profile logs found." -ForegroundColor Yellow }

# ---- Extract context around your exact errors ----
Write-Section "Log context around key error patterns"

$patternsNetwork = @(
    "ERROR:80070547",
    "Querying computer's fully qualified distinguished name failed",
    "Configuration information could not be read from the domain controller"
)

$patternsAds = @(
    "ERROR:80005000",
    "Failed to get computer's group SIDs"
)

$patternsProfile = @(
    "ErrorCode set to 5 - Message: Access is denied",
    "Access is denied",
    "FrxStatus:",
    "LoadProfile failed"
)

$ctx = @()
if ($networkLog) { $ctx += Tail-ContextFromLog -Path $networkLog.FullName -Patterns $patternsNetwork -ContextBefore 20 -ContextAfter 20 -MaxMatches 3 }
if ($adsLog)     { $ctx += Tail-ContextFromLog -Path $adsLog.FullName     -Patterns $patternsAds     -ContextBefore 20 -ContextAfter 20 -MaxMatches 3 }
if ($profileLog) { $ctx += Tail-ContextFromLog -Path $profileLog.FullName -Patterns $patternsProfile -ContextBefore 20 -ContextAfter 20 -MaxMatches 3 }

# ---- Machine identity / domain join ----
Write-Section "Machine identity & domain join"

try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Write-Host ("[OK]   Computer: {0}" -f $cs.Name) -ForegroundColor Green
    Write-Host ("[OK]   Domain joined: {0}" -f $cs.PartOfDomain) -ForegroundColor Green
    Write-Host ("[OK]   Domain: {0}" -f $cs.Domain) -ForegroundColor Green
} catch {
    Write-Host ("[FAIL] Unable to query Win32_ComputerSystem: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# ---- Secure channel test ----
Write-Section "Secure channel (trust) checks"

try {
    $sc = Test-ComputerSecureChannel -Verbose -ErrorAction Stop
    Write-Host ("[OK]   Test-ComputerSecureChannel: {0}" -f $sc) -ForegroundColor Green
} catch {
    Write-Host ("[FAIL] Secure channel test failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "[INFO] This commonly maps to DC reachability / machine account password / time skew issues." -ForegroundColor Yellow
}

# ---- DC discovery + connectivity ----
Write-Section "Domain Controller discovery & connectivity"

$dc = $null
try {
    $dc = (nltest /dsgetdc:($cs.Domain) 2>$null)
    if ($dc) {
        Write-Host "[OK]   nltest /dsgetdc output:" -ForegroundColor Green
        $dc | ForEach-Object { Write-Host ("       {0}" -f $_) }
    } else {
        Write-Host "[WARN] nltest returned no output (domain may be unknown or nltest blocked)." -ForegroundColor Yellow
    }
} catch {
    Write-Host ("[WARN] nltest failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

# DNS SRV check for LDAP
try {
    if ($cs -and $cs.Domain) {
        $srv = "_ldap._tcp.dc._msdcs.$($cs.Domain)"
        $srvRecords = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop
        Write-Host ("[OK]   DNS SRV records found: {0}" -f $srv) -ForegroundColor Green
        $srvRecords | Select-Object -First 5 | ForEach-Object {
            Write-Host ("       {0}:{1} (prio {2}, weight {3})" -f $_.NameTarget, $_.Port, $_.Priority, $_.Weight)
        }
    }
} catch {
    Write-Host ("[FAIL] DNS SRV lookup failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# ---- Time skew (Kerberos sensitive) ----
Write-Section "Time sync (Kerberos sensitivity)"

try {
    $wtm = w32tm /query /status 2>$null
    if ($wtm) {
        Write-Host "[OK]   w32tm /query /status:" -ForegroundColor Green
        $wtm | ForEach-Object { Write-Host ("       {0}" -f $_) }
    } else {
        Write-Host "[WARN] w32tm returned no output." -ForegroundColor Yellow
    }
} catch {
    Write-Host ("[WARN] w32tm failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

# ---- SYSTEM context sanity (who am I) ----
Write-Section "Execution context sanity"

try {
    $who = whoami
    Write-Host ("[OK]   Running as: {0}" -f $who) -ForegroundColor Green
} catch {
    Write-Host ("[WARN] whoami failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

# ---- Quick check: can we read computer DN / groups via .NET (no AD module required) ----
Write-Section "AD query test (computer DN + group SIDs)"

try {
    $domain = $cs.Domain
    if (-not [string]::IsNullOrWhiteSpace($domain)) {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)$))"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.PropertiesToLoad.Add("memberOf") | Out-Null
        $searcher.PageSize = 1

        $res = $searcher.FindOne()
        if ($res -and $res.Properties["distinguishedName"]) {
            $dn = $res.Properties["distinguishedName"][0]
            Write-Host ("[OK]   Computer DN: {0}" -f $dn) -ForegroundColor Green
            $groups = @($res.Properties["memberOf"])
            Write-Host ("[OK]   memberOf count: {0}" -f $groups.Count) -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Could not locate computer object via LDAP search (permissions/DC issues)." -ForegroundColor Red
        }
    } else {
        Write-Host "[WARN] Domain is empty/unknown; skipping LDAP test." -ForegroundColor Yellow
    }
} catch {
    Write-Host ("[FAIL] LDAP query failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# ---- Final summary object ----
Write-Section "Summary object"

$summary = [PSCustomObject]@{
    LatestNetworkLog        = $(if ($networkLog) { $networkLog.FullName } else { $null })
    LatestAdsComputerGroup  = $(if ($adsLog)     { $adsLog.FullName } else { $null })
    LatestProfileLog        = $(if ($profileLog) { $profileLog.FullName } else { $null })
    ContextMatches          = $ctx.Count
    DomainJoined            = $(try { (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { $null })
    Domain                  = $(try { (Get-CimInstance Win32_ComputerSystem).Domain } catch { $null })
    SecureChannelOk         = $(try { [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $false })
    RunningAs               = $(try { (whoami) } catch { $null })
}

$summary
