#############################################
#  FSLogix - Last 20 Error Messages (Local) #
#############################################
Write-Host "Collecting last 20 FSLogix errors across all local sources..." -ForegroundColor Cyan

$maxResults = 20
$results = @()

function Add-Result {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [datetime]$Time,
        [Parameter(Mandatory)] [string]$Message,
        [string]$Path = $null,
        [int]$LineNumber = $null
    )

    $script:results += [PSCustomObject]@{
        Time       = $Time
        Source     = $Source
        Message    = $Message
        Path       = $Path
        LineNumber = $LineNumber
    }
}

########################
# 1) FSLogix log files #
########################
$fslogixLogRoot = "C:\ProgramData\FSLogix\Logs"

if (Test-Path -LiteralPath $fslogixLogRoot) {
    Write-Host ("[OK]   FSLogix log root found: {0}" -f $fslogixLogRoot) -ForegroundColor Green

    $logFiles = Get-ChildItem -LiteralPath $fslogixLogRoot -Recurse -Filter "*.log" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 60   # limit for performance

    if ($logFiles) {
        Write-Host ("[OK]   Scanning {0} most recent log files..." -f $logFiles.Count) -ForegroundColor Green

        foreach ($lf in $logFiles) {
            try {
                # Look for error-ish lines (FSLogix commonly logs [ERROR], ERROR:########, or "ErrorCode set to")
                $matches = Select-String -LiteralPath $lf.FullName -Pattern "\[ERROR|\bERROR\b|ErrorCode set to|FrxStatus:\s*\d+" -ErrorAction Stop

                foreach ($m in $matches) {
                    # Try to parse FSLogix timestamp if present: [HH:mm:ss.fff]
                    $t = $lf.LastWriteTime
                    if ($m.Line -match "^\[(\d{2}):(\d{2}):(\d{2})\.(\d{3})\]") {
                        try {
                            $tod = [TimeSpan]::new([int]$matches[1], [int]$matches[2], [int]$matches[3], [int]$matches[4])
                            $t = $lf.LastWriteTime.Date.Add($tod)
                        } catch { }
                    }

                    Add-Result -Source "FSLogix Log" -Time $t -Message $m.Line.Trim() -Path $lf.FullName -LineNumber $m.LineNumber
                }
            } catch {
                # ignore file read errors
            }
        }
    } else {
        Write-Host "[WARN] No FSLogix .log files found under log root." -ForegroundColor Yellow
    }
} else {
    Write-Host ("[WARN] FSLogix log root not found: {0}" -f $fslogixLogRoot) -ForegroundColor Yellow
}

############################
# 2) Windows Event Logs    #
############################
Write-Host "Scanning Windows event logs for FSLogix-related errors..." -ForegroundColor Cyan

$startTime = (Get-Date).AddDays(-7)  # adjust if you want a wider window
$eventSources = @("FSLogix", "FSLogix Apps", "frx", "frxsvc", "frxccd", "frxdrv", "frxsession", "frxshell")

$eventLogsToCheck = @("Application", "System", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")

foreach ($logName in $eventLogsToCheck) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = $logName
            StartTime = $startTime
            Level     = 2  # Error
        } -ErrorAction Stop

        foreach ($e in $evts) {
            $provider = $e.ProviderName
            $msg = $e.Message
            $hit = $false

            # provider name check
            foreach ($s in $eventSources) {
                if ($provider -and ($provider -like "*$s*")) { $hit = $true; break }
            }

            # message check
            if (-not $hit -and $msg) {
                foreach ($s in $eventSources) {
                    if ($msg -like "*$s*") { $hit = $true; break }
                }
            }

            if ($hit) {
                $short = $msg
                if ($short) {
                    $short = $short -replace "\r\n"," | "
                    if ($short.Length -gt 500) { $short = $short.Substring(0,500) + "..." }
                } else {
                    $short = "(no message)"
                }

                Add-Result -Source ("EventLog: {0}" -f $logName) -Time $e.TimeCreated -Message ("{0} | EventId {1} | {2}" -f $provider, $e.Id, $short)
            }
        }
    } catch {
        Write-Host ("[WARN] Could not read event log: {0} | {1}" -f $logName, $_.Exception.Message) -ForegroundColor Yellow
    }
}

############################
# 3) Output Top 20 newest  #
############################
if (-not $results -or $results.Count -eq 0) {
    Write-Host "[WARN] No FSLogix-related error messages found in logs/events for the period scanned." -ForegroundColor Yellow
    return
}

$final = $results |
    Sort-Object Time -Descending |
    Select-Object -First $maxResults

Write-Host ""
Write-Host ("[OK]   Showing last {0} FSLogix-related errors (newest first):" -f $final.Count) -ForegroundColor Green
Write-Host ""

$final | Format-Table Time, Source, Path, LineNumber, Message -AutoSize

# Emit object for callers/logging
$final

