#Requires -Version 5.1
<#
.SYNOPSIS
    Pulls a targeted set of event-log entries for a Monday morning window and a
    Tuesday comparison window, then prints side-by-side counts, GPO processing
    times, Defender scan/signature activity and the raw events to the console.

.DESCRIPTION
    Logs / providers covered:
      System ......................... SMB client, Ntfs, VHDMP, disk
      Application .................... FSLogix-Apps, Winlogon, User Profile Service (1500-1599)
      Microsoft-Windows-FSLogix-Apps/Operational
      Microsoft-Windows-GroupPolicy/Operational (processing-time events 8000-8007, 5016)
      Microsoft-Windows-SMBClient/Connectivity   (30800-series)
      Microsoft-Windows-SMBClient/Operational    (30800-series)
      Microsoft-Windows-Windows Defender/Operational (scan 1000-1002, 1005, signatures 2000-2011)

.PARAMETER MondayDate
    Date of the Monday to examine. Defaults to the most recent Monday.
.PARAMETER TuesdayDate
    Date of the Tuesday to compare. Defaults to the day after MondayDate.
.PARAMETER StartHour / EndHour
    Window hours applied to both days (default 07:00-10:00).
.PARAMETER TuesdayStartHour / TuesdayEndHour
    Override the Tuesday window independently if needed.
.PARAMETER ComputerName
    Remote machine (default: local).
.PARAMETER ShowEvents
    Also print the raw event list for each window (can be long).
.PARAMETER MaxEvents
    Cap per log/query (default 5000).

.EXAMPLE
    .\Compare-MondayEventLogs.ps1
    .\Compare-MondayEventLogs.ps1 -MondayDate 2026-11-02 -ShowEvents
    .\Compare-MondayEventLogs.ps1 -ComputerName AVD-HOST-01 -TuesdayStartHour 8 -TuesdayEndHour 11
#>
[CmdletBinding()]
param(
    [datetime]$MondayDate,
    [datetime]$TuesdayDate,
    [ValidateRange(0,23)][int]$StartHour = 7,
    [ValidateRange(1,24)][int]$EndHour   = 10,
    [ValidateRange(0,23)][int]$TuesdayStartHour,
    [ValidateRange(1,24)][int]$TuesdayEndHour,
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$ShowEvents,
    [int]$MaxEvents = 5000
)

# ----------------------------------------------------------------------------
# Work out the two windows
# ----------------------------------------------------------------------------
if (-not $MondayDate) {
    $d = (Get-Date).Date
    while ($d.DayOfWeek -ne [DayOfWeek]::Monday) { $d = $d.AddDays(-1) }
    $MondayDate = $d
}
$MondayDate = $MondayDate.Date
if (-not $TuesdayDate) { $TuesdayDate = $MondayDate.AddDays(1) }
$TuesdayDate = $TuesdayDate.Date

if (-not $PSBoundParameters.ContainsKey('TuesdayStartHour')) { $TuesdayStartHour = $StartHour }
if (-not $PSBoundParameters.ContainsKey('TuesdayEndHour'))   { $TuesdayEndHour   = $EndHour }

$windows = @(
    [pscustomobject]@{ Name='Monday';  Start=$MondayDate.AddHours($StartHour);         End=$MondayDate.AddHours($EndHour) }
    [pscustomobject]@{ Name='Tuesday'; Start=$TuesdayDate.AddHours($TuesdayStartHour); End=$TuesdayDate.AddHours($TuesdayEndHour) }
)

# ----------------------------------------------------------------------------
# Query definitions (one FilterHashtable each; StartTime/EndTime added later)
# ----------------------------------------------------------------------------
$queries = @(
    @{ Label='System: SMB client / Ntfs / VHDMP / disk'
       Filter=@{ LogName='System'
                 ProviderName=@('Microsoft-Windows-SMBClient','Ntfs','Microsoft-Windows-Ntfs','vhdmp','Microsoft-Windows-VHDMP','disk','Microsoft-Windows-Disk') } }

    @{ Label='Application: FSLogix-Apps'
       Filter=@{ LogName='Application'; ProviderName=@('FSLogix-Apps','Microsoft-FSLogix-Apps') } }

    @{ Label='Application: Winlogon'
       Filter=@{ LogName='Application'; ProviderName=@('Microsoft-Windows-Winlogon','Winlogon') } }

    @{ Label='Application: User Profile Service 1500-series'
       Filter=@{ LogName='Application'; ProviderName='Microsoft-Windows-User Profiles Service'; ID=(1500..1599) } }

    @{ Label='FSLogix-Apps/Operational'
       Filter=@{ LogName='Microsoft-FSLogix-Apps/Operational' } }

    @{ Label='GroupPolicy/Operational (processing)'
       Filter=@{ LogName='Microsoft-Windows-GroupPolicy/Operational'; ID=@(4000..4007 + 5016 + 5017 + 5312 + 5317 + 6016 + 7016 + 8000..8007) } }

    @{ Label='SMBClient/Connectivity 30800-series'
       Filter=@{ LogName='Microsoft-Windows-SMBClient/Connectivity'; ID=(30800..30899) } }

    @{ Label='SMBClient/Operational 30800-series'
       Filter=@{ LogName='Microsoft-Windows-SMBClient/Operational'; ID=(30800..30899) } }

    @{ Label='Defender/Operational (scans + signatures)'
       Filter=@{ LogName='Microsoft-Windows-Windows Defender/Operational'; ID=@(1000,1001,1002,1005,2000,2001,2002,2010,2011) } }
)

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Get-WindowEvents {
    param($Query, $Window)
    $fh = $Query.Filter.Clone()
    $fh['StartTime'] = $Window.Start
    $fh['EndTime']   = $Window.End
    try {
        Get-WinEvent -ComputerName $ComputerName -FilterHashtable $fh -MaxEvents $MaxEvents -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    Window      = $Window.Name
                    Source      = $Query.Label
                    Time        = $_.TimeCreated
                    Log         = $_.LogName
                    Provider    = $_.ProviderName
                    Id          = $_.Id
                    Level       = $_.LevelDisplayName
                    User        = $_.UserId
                    Message     = ($_.Message -replace '\s+',' ').Trim()
                    MessageFull = $_.Message
                }
            }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-Warning ("[{0}] {1}: {2}" -f $Window.Name, $Query.Label, $_.Exception.Message)
        }
    }
}

function Get-Millis {
    param([string]$Text)
    if ($Text -match '(\d+)\s*millisecond') { return [int]$Matches[1] }
    return $null
}

function Write-Section($Title) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor Cyan
}

# ----------------------------------------------------------------------------
# Collect
# ----------------------------------------------------------------------------
Write-Section "Event log comparison on $ComputerName"
foreach ($w in $windows) {
    Write-Host ("  {0,-8} {1:ddd yyyy-MM-dd HH:mm} -> {2:HH:mm}" -f $w.Name, $w.Start, $w.End)
}

$all = foreach ($w in $windows) {
    foreach ($q in $queries) {
        Write-Verbose ("Querying {0} / {1}" -f $w.Name, $q.Label)
        Get-WindowEvents -Query $q -Window $w
    }
}
$all = @($all | Sort-Object Time)

if ($all.Count -eq 0) {
    Write-Host "`nNo matching events in either window." -ForegroundColor Yellow
    return
}

# ----------------------------------------------------------------------------
# 1. Counts per source, Monday vs Tuesday
# ----------------------------------------------------------------------------
Write-Section '1. Event counts by source'
$queries | ForEach-Object {
    $lbl = $_.Label
    $mon = @($all | Where-Object { $_.Window -eq 'Monday'  -and $_.Source -eq $lbl }).Count
    $tue = @($all | Where-Object { $_.Window -eq 'Tuesday' -and $_.Source -eq $lbl }).Count
    [pscustomobject]@{ Source=$lbl; Monday=$mon; Tuesday=$tue; Delta=$mon-$tue }
} | Format-Table -AutoSize

# ----------------------------------------------------------------------------
# 2. Counts per Provider/ID/Level
# ----------------------------------------------------------------------------
Write-Section '2. Event counts by Provider / ID / Level'
$all | Group-Object Provider, Id, Level | ForEach-Object {
    $mon = @($_.Group | Where-Object Window -eq 'Monday').Count
    $tue = @($_.Group | Where-Object Window -eq 'Tuesday').Count
    [pscustomobject]@{
        Provider = $_.Group[0].Provider
        Id       = $_.Group[0].Id
        Level    = $_.Group[0].Level
        Monday   = $mon
        Tuesday  = $tue
        Delta    = $mon - $tue
        Sample   = $_.Group[0].Message.Substring(0, [Math]::Min(90, $_.Group[0].Message.Length))
    }
} | Sort-Object { [Math]::Abs($_.Delta) } -Descending | Format-Table -AutoSize -Wrap

# ----------------------------------------------------------------------------
# 3. Errors & warnings only
# ----------------------------------------------------------------------------
Write-Section '3. Errors / Warnings / Critical'
$bad = $all | Where-Object { $_.Level -in 'Error','Warning','Critical' }
if ($bad) {
    $bad | Select-Object Window, Time, Provider, Id, Level, @{n='Message';e={ $_.Message.Substring(0,[Math]::Min(140,$_.Message.Length)) }} |
        Format-Table -AutoSize -Wrap
} else { Write-Host '  None.' -ForegroundColor Green }

# ----------------------------------------------------------------------------
# 4. Group Policy processing times
# ----------------------------------------------------------------------------
Write-Section '4. Group Policy processing times (ms)'
$gp = $all | Where-Object { $_.Log -eq 'Microsoft-Windows-GroupPolicy/Operational' } |
    ForEach-Object {
        $ms = Get-Millis $_.MessageFull
        if ($null -ne $ms) {
            [pscustomobject]@{
                Window   = $_.Window
                Time     = $_.Time
                Id       = $_.Id
                Millis   = $ms
                Detail   = $_.Message.Substring(0,[Math]::Min(110,$_.Message.Length))
            }
        }
    }
if ($gp) {
    $gp | Sort-Object Window, Time | Format-Table -AutoSize -Wrap
    Write-Host '  Summary by window and event ID:'
    $gp | Group-Object Window, Id | ForEach-Object {
        $m = $_.Group | Measure-Object Millis -Average -Maximum -Sum
        [pscustomobject]@{
            Window  = $_.Group[0].Window
            Id      = $_.Group[0].Id
            Count   = $_.Count
            AvgMs   = [int]$m.Average
            MaxMs   = $m.Maximum
            TotalMs = $m.Sum
        }
    } | Sort-Object Id, Window | Format-Table -AutoSize
} else { Write-Host '  No GPO timing events found.' }

# ----------------------------------------------------------------------------
# 5. Defender scans & signature updates
# ----------------------------------------------------------------------------
Write-Section '5. Defender scan / signature activity'
$def = $all | Where-Object { $_.Log -like '*Windows Defender*' }
if ($def) {
    $def | ForEach-Object {
        $kind = switch ($_.Id) {
            1000 {'Scan started'} 1001 {'Scan finished'} 1002 {'Scan cancelled'} 1005 {'Scan failed'}
            2000 {'Signatures updated'} 2001 {'Signature update FAILED'} 2002 {'Engine updated'}
            2010 {'Dynamic sigs updated'} 2011 {'Dynamic sigs removed'} default {"ID $($_.Id)"}
        }
        $scanType = ''
        if ($_.MessageFull -match 'Scan Type:\s*([^\r\n]+)') { $scanType = $Matches[1].Trim() }
        [pscustomobject]@{ Window=$_.Window; Time=$_.Time; Id=$_.Id; Event=$kind; ScanType=$scanType }
    } | Format-Table -AutoSize

    # Pair 1000 -> 1001 to estimate scan duration
    foreach ($w in $windows) {
        $starts = @($def | Where-Object { $_.Window -eq $w.Name -and $_.Id -eq 1000 } | Sort-Object Time)
        $ends   = @($def | Where-Object { $_.Window -eq $w.Name -and $_.Id -in 1001,1002,1005 } | Sort-Object Time)
        foreach ($s in $starts) {
            $e = $ends | Where-Object { $_.Time -gt $s.Time } | Select-Object -First 1
            if ($e) {
                Write-Host ("  {0,-8} scan {1:HH:mm:ss} -> {2:HH:mm:ss}  ({3:N1} min)" -f $w.Name, $s.Time, $e.Time, ($e.Time - $s.Time).TotalMinutes)
            } else {
                Write-Host ("  {0,-8} scan {1:HH:mm:ss} -> (no end event inside window)" -f $w.Name, $s.Time) -ForegroundColor Yellow
            }
        }
    }
} else { Write-Host '  No Defender events found.' }

# ----------------------------------------------------------------------------
# 6. Event density per 15-minute bucket
# ----------------------------------------------------------------------------
Write-Section '6. Events per 15-minute bucket'
$all | ForEach-Object {
    $b = $_.Time.Date.AddMinutes([Math]::Floor($_.Time.TimeOfDay.TotalMinutes / 15) * 15)
    [pscustomobject]@{ Window=$_.Window; Bucket=$b.ToString('HH:mm'); Level=$_.Level }
} | Group-Object Window, Bucket | ForEach-Object {
    [pscustomobject]@{
        Window = $_.Group[0].Window
        Bucket = $_.Group[0].Bucket
        Total  = $_.Count
        ErrWarn = @($_.Group | Where-Object { $_.Level -in 'Error','Warning','Critical' }).Count
    }
} | Sort-Object Window, Bucket | Format-Table -AutoSize

# ----------------------------------------------------------------------------
# 7. Raw events (optional)
# ----------------------------------------------------------------------------
if ($ShowEvents) {
    foreach ($w in $windows) {
        Write-Section "7. Raw events - $($w.Name)"
        $all | Where-Object Window -eq $w.Name |
            Select-Object Time, Provider, Id, Level, @{n='Message';e={ $_.Message.Substring(0,[Math]::Min(160,$_.Message.Length)) }} |
            Format-Table -AutoSize -Wrap
    }
} else {
    Write-Host "`nRe-run with -ShowEvents to print every event, or pipe `$all elsewhere." -ForegroundColor DarkGray
}

# Expose the collected events to the caller as well
$global:EventLogComparison = $all
Write-Host "`nAll $($all.Count) events also stored in `$global:EventLogComparison." -ForegroundColor DarkGray
