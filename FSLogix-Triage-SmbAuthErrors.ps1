#############################################
# FSLogix + SMB context collector (last 20)
# Works on Entra-native devices (no domain)
#############################################
Write-Host "Collecting FSLogix + SMB context..." -ForegroundColor Cyan

$fslogixProfileLogRoot = "C:\ProgramData\FSLogix\Logs\Profile"

$latestLog = Get-ChildItem -LiteralPath $fslogixProfileLogRoot -Filter "Profile-*.log" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $latestLog) {
    Write-Host ("[FAIL] No FSLogix Profile logs found under: {0}" -f $fslogixProfileLogRoot) -ForegroundColor Red
    return
}

Write-Host ("[OK]   Latest FSLogix Profile log: {0}" -f $latestLog.FullName) -ForegroundColor Green

# --- FSLogix: last 20 relevant failure lines ---
$fsxPatterns = @(
    "ERROR:0000052e",                  # 1326
    "ErrorCode set to 1326",
    "The user name or password is incorrect",
    "FindFile failed for path:",
    "LoadProfile failed",
    "Status set to 27:",
    "Access is denied",
    "ErrorCode set to 5"
)

$fsxHits = Select-String -LiteralPath $latestLog.FullName -Pattern $fsxPatterns -SimpleMatch -ErrorAction SilentlyContinue |
    Select-Object -Last 20

Write-Host ""
Write-Host "==================== FSLogix log (last 20 matching lines) ====================" -ForegroundColor Cyan
if ($fsxHits) {
    $fsxHits | ForEach-Object {
        Write-Host ("{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line.Trim())
    }
} else {
    Write-Host "[WARN] No matching failure lines found in latest Profile log." -ForegroundColor Yellow
}

# --- SMB Client logs around the last ~6 hours (tweak as needed) ---
$since = (Get-Date).AddHours(-6)

function Get-RecentWinEvents {
    param(
        [Parameter(Mandatory)] [string]$LogName,
        [int]$MaxEvents = 50
    )
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $since } -ErrorAction Stop |
            Select-Object -First $MaxEvents
    } catch {
        @()
    }
}

Write-Host ""
Write-Host "==================== SMBClient/Security (recent) ====================" -ForegroundColor Cyan
$smbSec = Get-RecentWinEvents -LogName "Microsoft-Windows-SMBClient/Security" -MaxEvents 50
if ($smbSec.Count -gt 0) {
    $smbSec | ForEach-Object {
        Write-Host ("[{0}] Id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\r\n"," " -replace "\s+"," ").Trim())
    }
} else {
    Write-Host "[WARN] No SMBClient/Security events found (or log not enabled)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================== SMBClient/Connectivity (recent) ====================" -ForegroundColor Cyan
$smbConn = Get-RecentWinEvents -LogName "Microsoft-Windows-SMBClient/Connectivity" -MaxEvents 50
if ($smbConn.Count -gt 0) {
    $smbConn | ForEach-Object {
        Write-Host ("[{0}] Id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\r\n"," " -replace "\s+"," ").Trim())
    }
} else {
    Write-Host "[WARN] No SMBClient/Connectivity events found (or log not enabled)." -ForegroundColor Yellow
}

# --- Summary object ---
$summary = [PSCustomObject]@{
    LatestProfileLog      = $latestLog.FullName
    LatestProfileLogTime  = $latestLog.LastWriteTime
    FslogixMatchCount     = $(if ($fsxHits) { $fsxHits.Count } else { 0 })
    SmbSecurityEventCount = $(if ($smbSec) { $smbSec.Count } else { 0 })
    SmbConnEventCount     = $(if ($smbConn) { $smbConn.Count } else { 0 })
    Since                 = $since
}

Write-Host ""
Write-Host "==================== Summary ====================" -ForegroundColor Cyan
$summary