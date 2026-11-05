#Requires -Version 5.1
<#
.SYNOPSIS
    Console inventory of scheduled tasks, startup/logon scripts and everything else that runs at boot or
    at user logon on a Citrix VDA / session host using FSLogix profile containers.

.DESCRIPTION
    Windows PowerShell 5.1 only. Run elevated on a VDA (for MCS/PVS, run it on a provisioned machine, not just
    the master image, so you see what the running catalog actually has). Everything is printed to the console;
    pipe to Out-File / Tee-Object if you want to keep a copy, e.g.

        .\Get-StartupInventory.ps1 | Tee-Object -FilePath "$env:COMPUTERNAME-inventory.txt"

    Sections:
      1. Host summary (OS, last boot, uptime - tells you if the VDA was rebooted over the weekend)
      2. Citrix VDA / FSLogix / Profile Management / WEM agents and FSLogix configuration
      3. Scheduled tasks (non-Microsoft by default) with schedule, last/next run and result
         - anything that runs Sat/Sun/Mon or daily, or last ran over the most recent weekend, is flagged *
      4. Noteworthy Microsoft tasks (Defrag, Defender, Windows Update, chkdsk, data integrity scan, maintenance)
      5. Group Policy startup and logon scripts, Run/RunOnce keys, Startup folders, Winlogon
      6. Active Setup components (run once per user at first logon on each VDA)
      7. WMI permanent event subscriptions
      8. Auto-start services whose binary lives outside \Windows (AV, monitoring, management agents etc.)
      9. Data Deduplication (only prints if the feature is present - normally not on a VDA)
     10. Microsoft Defender scan schedule and exclusions (if present)

.PARAMETER IncludeMicrosoftTasks
    Include every task under \Microsoft\* in section 2 (very noisy; section 3 already covers the usual suspects).

.PARAMETER IncludeDisabled
    Include disabled scheduled tasks.
#>

[CmdletBinding()]
param(
    [switch]$IncludeMicrosoftTasks,
    [switch]$IncludeDisabled,
    [switch]$ShowActions          # print the command line each task runs (long; off by default)
)

$ErrorActionPreference = 'Continue'

# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 110) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 110) -ForegroundColor Cyan
}

function Write-Sub {
    param([string]$Title)
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Format-RunTime {
    # Task Scheduler reports "never run" as 30/11/1999 00:00:00
    param($Time)
    if (-not $Time -or $Time.Year -lt 2000) { return '-' }
    return $Time.ToString('ddd dd/MM HH:mm')
}

function Format-TaskResult {
    param($Code)
    if ($null -eq $Code) { return '' }
    switch ([uint32]$Code) {
        0          { return 'OK' }
        0x41300    { return 'ready' }
        0x41301    { return 'RUNNING' }
        0x41302    { return 'disabled' }
        0x41303    { return 'never run' }
        0x41304    { return 'no more runs' }
        0x41305    { return 'not scheduled' }
        0x41306    { return 'terminated' }
        0x41325    { return 'queued' }
        0x800704DD { return 'not logged on' }
        default    { return ('0x{0:X}' -f [uint32]$Code) }
    }
}

function Get-TaskSchedule {
    # One readable line summarising all triggers on a task
    param($Task)
    $txt = @($Task.Triggers | ForEach-Object { Get-TriggerText $_ }) -join '  |  '
    if (-not $txt.Trim()) { return '(on demand)' }
    return $txt
}

function Get-TriggerText {
    param($Trigger)

    $class = $Trigger.CimClass.CimClassName
    $parts = New-Object System.Collections.Generic.List[string]

    # Time-of-day from the start boundary (the date part is usually a meaningless 2008/2011 placeholder)
    $tod = ''
    if ($Trigger.StartBoundary -and $Trigger.StartBoundary -match 'T(\d{2}:\d{2})') { $tod = $Matches[1] }

    switch ($class) {
        'MSFT_TaskDailyTrigger' {
            if ($Trigger.DaysInterval -gt 1) { $parts.Add("every $($Trigger.DaysInterval) days at $tod") } else { $parts.Add("daily at $tod") }
        }
        'MSFT_TaskWeeklyTrigger' {
            $s = "weekly $(ConvertTo-DayNames $Trigger.DaysOfWeek) at $tod"
            if ($Trigger.WeeksInterval -gt 1) { $s += " (every $($Trigger.WeeksInterval) wks)" }
            $parts.Add($s)
        }
        'MSFT_TaskMonthlyTrigger'    { $parts.Add("monthly at $tod (day mask $($Trigger.DaysOfMonth))") }
        'MSFT_TaskMonthlyDOWTrigger' { $parts.Add("monthly $(ConvertTo-DayNames $Trigger.DaysOfWeek) at $tod (week mask $($Trigger.WeeksOfMonth))") }
        'MSFT_TaskTimeTrigger'       { if ($Trigger.Repetition.Interval) { $parts.Add('repeating') } else { $parts.Add("once $($Trigger.StartBoundary)") } }
        'MSFT_TaskEventTrigger'      { $parts.Add('on event') }
        'MSFT_TaskBootTrigger'       { $parts.Add('at boot' + $(if ($Trigger.Delay) { " +$(ConvertFrom-Iso8601Duration $Trigger.Delay)" })) }
        'MSFT_TaskLogonTrigger'      { $parts.Add('at logon' + $(if ($Trigger.UserId) { " ($($Trigger.UserId))" })) }
        'MSFT_TaskIdleTrigger'       { $parts.Add('when idle') }
        'MSFT_TaskRegistrationTrigger'      { $parts.Add('on registration') }
        'MSFT_TaskSessionStateChangeTrigger' { $parts.Add('on session change') }
        default                      { $parts.Add(($class -replace '^MSFT_Task', '' -replace 'Trigger$', '')) }
    }

    if ($Trigger.Repetition -and $Trigger.Repetition.Interval) {
        $rep = "every $(ConvertFrom-Iso8601Duration $Trigger.Repetition.Interval)"
        if ($Trigger.Repetition.Duration) { $rep += " for $(ConvertFrom-Iso8601Duration $Trigger.Repetition.Duration)" }
        $parts.Add($rep)
    }
    if ($Trigger.Enabled -eq $false) { $parts.Add('[trigger disabled]') }

    return ($parts -join ' ')
}

function ConvertFrom-Iso8601Duration {
    # PT6H -> 6h, P3D -> 3d, PT1H30M -> 1h30m
    param([string]$Iso)
    if (-not $Iso) { return '' }
    $out = ''
    if ($Iso -match 'P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?') {
        if ($Matches[1]) { $out += "$($Matches[1])d" }
        if ($Matches[2]) { $out += "$($Matches[2])h" }
        if ($Matches[3]) { $out += "$($Matches[3])m" }
        if ($Matches[4]) { $out += "$($Matches[4])s" }
    }
    if ($out) { return $out } else { return $Iso }
}

function ConvertTo-DayNames {
    # Task Scheduler DaysOfWeek bitmask: Sun=1 Mon=2 Tue=4 Wed=8 Thu=16 Fri=32 Sat=64
    param([int]$Mask)
    $names = 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
    $out = for ($i = 0; $i -lt 7; $i++) { if ($Mask -band [int][math]::Pow(2, $i)) { $names[$i] } }
    if ($out) { return ($out -join ',') } else { return '(none)' }
}

function Get-ActionText {
    param($Action)
    if ($Action.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
        $s = $Action.Execute
        if ($Action.Arguments)        { $s += " $($Action.Arguments)" }
        if ($Action.WorkingDirectory) { $s += "   [cwd: $($Action.WorkingDirectory)]" }
        return $s
    }
    elseif ($Action.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') {
        return "COM handler $($Action.ClassId) $($Action.Data)"
    }
    else { return $Action.CimClass.CimClassName }
}

function Write-TaskTable {
    # Aligned, colour-coded table of task rows produced in sections 2 and 3
    param($Rows, [string]$Title, [switch]$SortByNext, [string]$TrimPrefix = '')

    if ($Title) { Write-Sub $Title }
    if (-not $Rows) { Write-Host "      (none)" -ForegroundColor DarkGray; return }

    if ($SortByNext) {
        $Rows = $Rows | Sort-Object @{ e = { if ($_._next -and $_._next.Year -gt 2000) { 0 } else { 1 } } }, _next
    }

    $taskW = [math]::Min(60, (($Rows | ForEach-Object { ($_.Task -replace [regex]::Escape($TrimPrefix), '').Length } | Measure-Object -Maximum).Maximum))
    $fmt   = "  {0,-4} {1,-$taskW} {2,-9} {3,-16} {4,-11} {5,-16} {6}"

    Write-Host ($fmt -f 'Flag', 'Task', 'State', 'Last run', 'Result', 'Next run', 'Schedule') -ForegroundColor White
    Write-Host ($fmt -f '----', ('-' * $taskW), '-----', '--------', '------', '--------', '--------') -ForegroundColor DarkGray

    foreach ($r in $Rows) {
        $name = $r.Task -replace [regex]::Escape($TrimPrefix), ''
        if ($name.Length -gt $taskW) { $name = $name.Substring(0, $taskW - 1) + '~' }
        $colour = 'Gray'
        if ($r.State -eq 'Disabled')    { $colour = 'DarkGray' }
        elseif ($r.Flag)                { $colour = 'Magenta' }
        elseif ($r.State -eq 'Running') { $colour = 'Green' }
        elseif ($r.Result -ne 'OK' -and $r.Result -ne 'never run' -and $r.Result -ne 'ready' -and $r.Result -ne '') { $colour = 'Yellow' }

        $flag = if ($r.Flag) { '*' } else { '' }
        Write-Host ($fmt -f $flag, $name, $r.State, $r.LastRun, $r.Result, $r.NextRun, $r.Schedule) -ForegroundColor $colour
        if ($ShowActions -and $r.Actions) {
            Write-Host ("  {0,-4} {1,-$taskW} -> {2}" -f '', '', $r.Actions) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host "  * = runs Sat/Sun/Mon or daily, or last ran during the weekend window.  Yellow = non-OK last result.  Use -ShowActions for command lines." -ForegroundColor DarkGray
}

function Test-WeekendOrMonday {
    # True if any trigger includes Sat/Sun/Mon, or the task last ran during the most recent weekend window.
    param($Task, $Info, [datetime]$WeekendStart, [datetime]$WeekendEnd)

    foreach ($t in $Task.Triggers) {
        $c = $t.CimClass.CimClassName
        if ($c -in 'MSFT_TaskWeeklyTrigger', 'MSFT_TaskMonthlyDOWTrigger') {
            if ($t.DaysOfWeek -band 1 -or $t.DaysOfWeek -band 2 -or $t.DaysOfWeek -band 64) { return $true }
        }
        if ($c -eq 'MSFT_TaskDailyTrigger') { return $true }   # runs every day incl. Sun night / Mon morning
    }
    if ($Info.LastRunTime -and $Info.LastRunTime -ge $WeekendStart -and $Info.LastRunTime -le $WeekendEnd) { return $true }
    return $false
}

function Split-CommandLine {
    # "C:\Program Files\x\y.exe" /a /b   ->  @{ Exe = 'C:\Program Files\x\y.exe'; Args = '/a /b' }
    param([string]$Cmd)
    $Cmd = [string]$Cmd
    $Cmd = $Cmd.Trim()
    if (-not $Cmd) { return @{ Exe = ''; Args = '' } }
    if ($Cmd.StartsWith('"')) {
        $end = $Cmd.IndexOf('"', 1)
        if ($end -gt 0) { return @{ Exe = $Cmd.Substring(1, $end - 1); Args = $Cmd.Substring($end + 1).Trim() } }
    }
    # Unquoted: split at first space after the .exe (or at first space if no .exe)
    $m = [regex]::Match($Cmd, '^(.*?\.(exe|cmd|bat|vbs|ps1|dll))(\s+.*)?$', 'IgnoreCase')
    if ($m.Success) { return @{ Exe = $m.Groups[1].Value; Args = $m.Groups[3].Value.Trim() } }
    $sp = $Cmd.IndexOf(' ')
    if ($sp -gt 0) { return @{ Exe = $Cmd.Substring(0, $sp); Args = $Cmd.Substring($sp + 1).Trim() } }
    return @{ Exe = $Cmd; Args = '' }
}

function Test-ExePresent {
    param([string]$Exe)
    if (-not $Exe) { return $true }
    $p = [Environment]::ExpandEnvironmentVariables($Exe)
    if ($p -match '^[A-Za-z]:\\') { return (Test-Path -LiteralPath $p) }
    # bare name like grpconv / rundll32 - assume on PATH
    return $true
}

function Show-RunKeys {
    param([hashtable[]]$Keys)   # @{ Label='HKLM Run'; Path='HKLM:\...' }

    $rows = foreach ($k in $Keys) {
        if (-not (Test-Path $k.Path)) { continue }
        $item = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue
        $vals = $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }
        foreach ($v in $vals) {
            $split = Split-CommandLine $v.Value
            [pscustomobject]@{
                Key     = $k.Label
                Name    = $v.Name
                Program = $split.Exe
                Args    = $split.Args
                Missing = -not (Test-ExePresent $split.Exe)
            }
        }
    }

    if (-not $rows) { Write-Host "      (nothing registered)" -ForegroundColor DarkGray; return }

    $rows  = @($rows)
    $keyW  = [math]::Max(3, (@($rows | ForEach-Object { $_.Key.Length })     | Measure-Object -Maximum).Maximum)
    $nameW = [math]::Max(4, [math]::Min(42, (@($rows | ForEach-Object { $_.Name.Length }) | Measure-Object -Maximum).Maximum))
    $progW = [math]::Max(7, [math]::Min(70, (@($rows | ForEach-Object { $_.Program.Length }) | Measure-Object -Maximum).Maximum))
    $fmt   = "  {0,-$keyW}  {1,-$nameW}  {2,-$progW}  {3}"
    $argsCol = 2 + $keyW + 2 + $nameW + 2 + $progW + 2          # column where Arguments starts
    $argsMax = 90                                                # inline arguments longer than this go on continuation lines

    Write-Host ($fmt -f 'Key', 'Name', 'Program', 'Arguments') -ForegroundColor White
    Write-Host ($fmt -f ('-' * $keyW), ('-' * $nameW), ('-' * $progW), '---------') -ForegroundColor DarkGray

    $lastKey = ''
    foreach ($r in $rows) {
        if ($lastKey -and $r.Key -ne $lastKey) { Write-Host '' }
        $lastKey = $r.Key
        $name = $r.Name; if ($name.Length -gt $nameW) { $name = $name.Substring(0, $nameW - 1) + '~' }
        $prog = $r.Program
        if ($prog.Length -gt $progW) { $prog = '~' + $prog.Substring($prog.Length - $progW + 1) }   # keep the file name end
        $args = ($r.Args -replace '\s+', ' ').Trim()
        $colour = if ($r.Missing) { 'Yellow' } elseif ($r.Key -like '*RunOnce*') { 'DarkGray' } else { 'Gray' }

        if ($args.Length -le $argsMax) {
            if ($r.Missing) { $args = "(FILE MISSING) $args" }
            Write-Host ($fmt -f $r.Key, $name, $prog, $args) -ForegroundColor $colour
        }
        else {
            # Long command: row shows the program, full arguments follow on wrapped, indented lines
            Write-Host ($fmt -f $r.Key, $name, $prog, $(if ($r.Missing) { '(FILE MISSING)  full command below:' } else { 'full command below:' })) -ForegroundColor $colour
            $wrap = 110
            $pos = 0
            while ($pos -lt $args.Length) {
                $len = [math]::Min($wrap, $args.Length - $pos)
                # break on a space where possible
                if ($pos + $len -lt $args.Length) {
                    $sp = $args.LastIndexOf(' ', $pos + $len - 1, $len)
                    if ($sp -gt $pos) { $len = $sp - $pos + 1 }
                }
                Write-Host ((' ' * $argsCol) + $args.Substring($pos, $len)) -ForegroundColor $colour
                $pos += $len
            }
        }
    }

    $absent = $Keys | Where-Object { -not (Test-Path $_.Path) } | ForEach-Object Label
    if ($absent) { Write-Host ''; Write-Host ("  Not present: {0}" -f ($absent -join ', ')) -ForegroundColor DarkGray }
}

function Get-ShortcutTarget {
    param([string]$LnkPath)
    try {
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($LnkPath)
        $t = $lnk.TargetPath
        if ($lnk.Arguments) { $t += " $($lnk.Arguments)" }
        return $t
    }
    catch { return '' }
}

function Show-GpoScripts {
    param([string]$RegPath, [string]$Label)
    Write-Host "  $Label  [$RegPath]" -ForegroundColor White
    if (-not (Test-Path $RegPath)) { Write-Host "      (not present)" -ForegroundColor DarkGray; return }

    $found = $false
    foreach ($gpoKey in Get-ChildItem $RegPath -ErrorAction SilentlyContinue) {
        $gpo = Get-ItemProperty $gpoKey.PSPath -ErrorAction SilentlyContinue
        foreach ($scriptKey in Get-ChildItem $gpoKey.PSPath -ErrorAction SilentlyContinue) {
            $s = Get-ItemProperty $scriptKey.PSPath -ErrorAction SilentlyContinue
            $found = $true
            Write-Host ("      GPO       : {0}  ({1})" -f $gpo.DisplayName, $gpo.GPOName)
            Write-Host ("      Script    : {0} {1}" -f $s.Script, $s.Parameters)
            if ($gpo.FileSysPath) { Write-Host ("      SysVol    : {0}" -f $gpo.FileSysPath) }
            if ($s.ExecTime)      { Write-Host ("      Last exec : {0}" -f $s.ExecTime) }
            Write-Host ''
        }
    }
    if (-not $found) { Write-Host "      (no scripts registered)" -ForegroundColor DarkGray }
}

# ----------------------------------------------------------------------------------------------
# 1. Host summary
# ----------------------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Section "STARTUP / SCHEDULED WORK INVENTORY - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
if (-not $isAdmin) {
    Write-Host "  WARNING: not running elevated - some tasks, WMI subscriptions and registry keys may be hidden." -ForegroundColor Red
}

$os = Get-CimInstance Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
Write-Host ("  OS         : {0} ({1})" -f $os.Caption, $os.Version)
Write-Host ("  Last boot  : {0:yyyy-MM-dd HH:mm:ss}  ({1})" -f $os.LastBootUpTime, $os.LastBootUpTime.DayOfWeek)
Write-Host ("  Uptime     : {0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
Write-Host ("  Domain     : {0}" -f (Get-CimInstance Win32_ComputerSystem).Domain)

# Most recent weekend window: Friday 18:00 -> Monday 09:00
$today = (Get-Date).Date
$daysSinceMonday = ([int](Get-Date).DayOfWeek + 6) % 7
$lastMonday   = $today.AddDays(-$daysSinceMonday)
$weekendStart = $lastMonday.AddDays(-3).AddHours(18)   # Friday 18:00
$weekendEnd   = $lastMonday.AddHours(9)                # Monday 09:00
Write-Host ("  Weekend window used for the * flag: {0:ddd dd MMM HH:mm} -> {1:ddd dd MMM HH:mm}" -f $weekendStart, $weekendEnd)
if ($os.LastBootUpTime -ge $weekendStart -and $os.LastBootUpTime -le $weekendEnd) {
    Write-Host "  NOTE: this host was rebooted during the weekend window (cold caches / first-logon work on Monday)." -ForegroundColor Magenta
}

# ----------------------------------------------------------------------------------------------
# 2. Citrix / FSLogix / UPM / WEM agents
# ----------------------------------------------------------------------------------------------
Write-Section "CITRIX / FSLOGIX / PROFILE AGENTS"

function Get-FileVer { param([string]$Path) try { (Get-Item -LiteralPath ([Environment]::ExpandEnvironmentVariables($Path)) -ErrorAction Stop).VersionInfo.FileVersion } catch { '' } }

Write-Sub "Agent services"
$agentSvcs = @(
    @{ Name = 'BrokerAgent';                 Label = 'Citrix VDA (Broker Agent)' },
    @{ Name = 'ctxProfile';                  Label = 'Citrix Profile Management' },
    @{ Name = 'Citrix WEM Agent Host Service'; Label = 'Citrix WEM agent' },
    @{ Name = 'Norskale Agent Host Service'; Label = 'Citrix WEM agent (legacy name)' },
    @{ Name = 'frxsvc';                      Label = 'FSLogix Apps service' },
    @{ Name = 'frxccds';                     Label = 'FSLogix Cloud Cache' },
    @{ Name = 'CtxUvi';                      Label = 'Citrix UVI (hook service)' },
    @{ Name = 'CtxAppVService';              Label = 'Citrix App-V' },
    @{ Name = 'picaSvc2';                    Label = 'Citrix ICA service' }
)
$fmt = "  {0,-34} {1,-30} {2,-9} {3,-11} {4}"
Write-Host ($fmt -f 'Agent', 'Service', 'State', 'Start', 'Version') -ForegroundColor White
Write-Host ($fmt -f ('-' * 34), ('-' * 30), '-----', '-----', '-------') -ForegroundColor DarkGray
foreach ($a in $agentSvcs) {
    $s = Get-CimInstance Win32_Service -Filter "Name='$($a.Name)'" -ErrorAction SilentlyContinue
    if (-not $s) { continue }
    $exe = (Split-CommandLine $s.PathName).Exe
    $colour = if ($s.State -eq 'Running') { 'Gray' } else { 'Yellow' }
    Write-Host ($fmt -f $a.Label, $s.Name, $s.State, $s.StartMode, (Get-FileVer $exe)) -ForegroundColor $colour
}

Write-Sub "FSLogix configuration (HKLM\SOFTWARE\FSLogix)"
$fsKeys = @(
    @{ Label = 'Profiles'; Path = 'HKLM:\SOFTWARE\FSLogix\Profiles' },
    @{ Label = 'ODFC';     Path = 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC' },
    @{ Label = 'ODFC';     Path = 'HKLM:\SOFTWARE\FSLogix\ODFC' },
    @{ Label = 'Apps';     Path = 'HKLM:\SOFTWARE\FSLogix\Apps' },
    @{ Label = 'Logging';  Path = 'HKLM:\SOFTWARE\FSLogix\Logging' }
)
$interesting = 'Enabled', 'VHDLocations', 'CCDLocations', 'VolumeType', 'SizeInMBs', 'IsDynamic', 'FlipFlopProfileDirectoryName',
               'DeleteLocalProfileWhenVHDShouldApply', 'PreventLoginWithFailure', 'PreventLoginWithTempProfile',
               'ProfileType', 'VHDAccessMode', 'ReAttachIntervalSeconds', 'ReAttachRetryCount', 'LockedRetryCount',
               'LockedRetryInterval', 'VHDCompactDisk', 'VHDXSectorSize', 'RoamSearch', 'RoamIdentity',
               'RedirXMLSourceFolder', 'ConcurrentUserSessions', 'KeepLocalDir', 'ObjectSpecificVHDs',
               'AccessNetworkAsComputerObject', 'NoProfileContainingFolder', 'RoamRecycleBin', 'CleanupInvalidSessions',
               'LogDir', 'LogFileKeepingPeriod', 'LoggingEnabled', 'LoggingLevel', 'InstallPath', 'RoamSearch'
foreach ($k in $fsKeys) {
    if (-not (Test-Path $k.Path)) { continue }
    $p = Get-ItemProperty $k.Path -ErrorAction SilentlyContinue
    $props = $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $interesting -contains $_.Name }
    if (-not $props) { continue }
    Write-Host "  [$($k.Label)]  $($k.Path)" -ForegroundColor White
    foreach ($pr in $props | Sort-Object Name) {
        $v = $pr.Value; if ($v -is [array]) { $v = $v -join ' ; ' }
        $colour = 'Gray'
        if ($pr.Name -eq 'Enabled' -and $v -eq 1) { $colour = 'Green' }
        Write-Host ("      {0,-38} {1}" -f $pr.Name, $v) -ForegroundColor $colour
    }
}
$frx = 'C:\Program Files\FSLogix\Apps\frxsvc.exe'
if (Test-Path $frx) { Write-Host ("  FSLogix version: {0}" -f (Get-FileVer $frx)) }
else { Write-Host "  FSLogix does not appear to be installed on this host." -ForegroundColor Yellow }

Write-Sub "Citrix Profile Management policy state"
$upm = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager' -ErrorAction SilentlyContinue
if ($upm -and $null -ne $upm.ServiceActive) {
    $colour = if ($upm.ServiceActive -eq 1) { 'Yellow' } else { 'Gray' }
    Write-Host ("  UPM ServiceActive = {0}  {1}" -f $upm.ServiceActive, $(if ($upm.ServiceActive -eq 1) { '<-- UPM active alongside FSLogix: check this is intended' })) -ForegroundColor $colour
    if ($upm.PathToUserStore) { Write-Host ("  PathToUserStore   = {0}" -f $upm.PathToUserStore) }
}
else { Write-Host "  No UPM policy present (or ServiceActive not set)." -ForegroundColor DarkGray }

Write-Sub "Citrix VDA registration"
$vda = Get-ItemProperty 'HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent' -ErrorAction SilentlyContinue
if ($vda) {
    foreach ($n in 'ListOfDDCs', 'RegistrationState', 'ProvisioningType') { if ($vda.$n) { Write-Host ("      {0,-20} {1}" -f $n, $vda.$n) } }
}
$pvs = Get-Service -Name 'BNDevice' -ErrorAction SilentlyContinue
$mcs = Test-Path 'HKLM:\SOFTWARE\Citrix\MachineIdentityServiceAgent'
Write-Host ("      {0,-20} {1}" -f 'Provisioning', $(if ($pvs) { 'PVS (BNDevice service present)' } elseif ($mcs) { 'MCS (MachineIdentityServiceAgent present)' } else { 'none detected / persistent' }))

# ----------------------------------------------------------------------------------------------
# 3. Scheduled tasks
# ----------------------------------------------------------------------------------------------
Write-Section "SCHEDULED TASKS $(if ($IncludeMicrosoftTasks) {'(all)'} else {'(non-Microsoft; use -IncludeMicrosoftTasks for everything)'})"

try {
    $allTasks = Get-ScheduledTask -ErrorAction Stop
}
catch {
    Write-Host "  Get-ScheduledTask failed: $($_.Exception.Message)" -ForegroundColor Red
    $allTasks = @()
}

$tasks = $allTasks
if (-not $IncludeMicrosoftTasks) { $tasks = $tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } }
if (-not $IncludeDisabled)       { $tasks = $tasks | Where-Object { $_.State -ne 'Disabled' } }

$rows = foreach ($t in ($tasks | Sort-Object TaskPath, TaskName)) {
    $info = $null
    try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}

    $flag = ''
    if (Test-WeekendOrMonday -Task $t -Info $info -WeekendStart $weekendStart -WeekendEnd $weekendEnd) { $flag = '[WEEKEND/MON]' }

    [pscustomobject]@{
        Flag     = $flag
        Task     = "$($t.TaskPath)$($t.TaskName)"
        State    = $t.State
        RunAs    = $t.Principal.UserId
        LastRun  = Format-RunTime $(if ($info) { $info.LastRunTime })
        Result   = Format-TaskResult $(if ($info) { $info.LastTaskResult })
        NextRun  = Format-RunTime $(if ($info) { $info.NextRunTime })
        Schedule = Get-TaskSchedule $t
        Actions  = (($t.Actions | ForEach-Object { Get-ActionText $_ }) -join ' | ')
        _next    = if ($info) { $info.NextRunTime } else { $null }
    }
}

Write-TaskTable -Rows $rows -Title "$(@($rows).Count) tasks, sorted by next run" -SortByNext

# ----------------------------------------------------------------------------------------------
# 4. Noteworthy Microsoft tasks (I/O heavy, usually weekend-scheduled)
# ----------------------------------------------------------------------------------------------
Write-Section "NOTEWORTHY MICROSOFT TASKS (defrag / defender / dedup / windows update / chkdsk / integrity / backup / VSS / maintenance)"

$patterns = '\Microsoft\Windows\Defrag\*', '\Microsoft\Windows Defender\*', '\Microsoft\Windows\Deduplication\*',
            '\Microsoft\Windows\WindowsUpdate\*', '\Microsoft\Windows\UpdateOrchestrator\*', '\Microsoft\Windows\Chkdsk\*',
            '\Microsoft\Windows\Data Integrity Scan\*', '\Microsoft\Windows\Storage Tiers Management\*',
            '\Microsoft\Windows\Backup\*', '\Microsoft\Windows\Shadow Copy*', '\Microsoft\Windows\DiskCleanup\*',
            '\Microsoft\Windows\Maintenance\*', '\Microsoft\Windows\Windows Error Reporting\*'

$ms = $allTasks | Where-Object { $p = $_.TaskPath + $_.TaskName; ($patterns | Where-Object { $p -like $_ }) }
$msRows = foreach ($t in ($ms | Sort-Object TaskPath, TaskName)) {
    $info = $null
    try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
    $flag = ''
    if (Test-WeekendOrMonday -Task $t -Info $info -WeekendStart $weekendStart -WeekendEnd $weekendEnd) { $flag = '*' }
    [pscustomobject]@{
        Flag     = $flag
        Task     = "$($t.TaskPath)$($t.TaskName)"
        State    = $t.State
        RunAs    = $t.Principal.UserId
        LastRun  = Format-RunTime $(if ($info) { $info.LastRunTime })
        Result   = Format-TaskResult $(if ($info) { $info.LastTaskResult })
        NextRun  = Format-RunTime $(if ($info) { $info.NextRunTime })
        Schedule = Get-TaskSchedule $t
        Actions  = (($t.Actions | ForEach-Object { Get-ActionText $_ }) -join ' | ')
        _next    = if ($info) { $info.NextRunTime } else { $null }
    }
}
Write-TaskTable -Rows $msRows -Title "Paths shown relative to \Microsoft\Windows\" -TrimPrefix '\Microsoft\Windows\'

# Automatic maintenance window (hosts many of the above)
$maint = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance' -ErrorAction SilentlyContinue
if ($maint) {
    Write-Sub "Automatic Maintenance window (hosts Defrag, Defender, Dedup and others)"
    $maint.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        $v = $_.Value
        if ($_.Name -eq 'Activation Boundary' -and $v -match 'T(\d{2}:\d{2})') { $v = "$v  (daily at $($Matches[1]))" }
        Write-Host ("      {0,-30} {1}" -f $_.Name, $v)
    }
}

# ----------------------------------------------------------------------------------------------
# 5. Startup/logon scripts and run keys
# ----------------------------------------------------------------------------------------------
Write-Section "GROUP POLICY STARTUP AND LOGON SCRIPTS"

Show-GpoScripts -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup'  -Label 'Computer STARTUP scripts'
Show-GpoScripts -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown' -Label 'Computer SHUTDOWN scripts'
Show-GpoScripts -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon'    -Label 'User LOGON scripts registered machine-wide'
Show-GpoScripts -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff'   -Label 'User LOGOFF scripts registered machine-wide'

# Per-user logon scripts recorded in machine state for every user who has logged on (one block per SID)
$stateRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State'
$userStates = Get-ChildItem $stateRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'S-1-5-21-*' }
$seen = @{}
foreach ($u in $userStates) {
    $logon = Join-Path $u.PSPath 'Scripts\Logon'
    if (-not (Test-Path $logon)) { continue }
    foreach ($gpoKey in Get-ChildItem $logon -ErrorAction SilentlyContinue) {
        $gpo = Get-ItemProperty $gpoKey.PSPath -ErrorAction SilentlyContinue
        foreach ($scriptKey in Get-ChildItem $gpoKey.PSPath -ErrorAction SilentlyContinue) {
            $s = Get-ItemProperty $scriptKey.PSPath -ErrorAction SilentlyContinue
            $id = "$($gpo.GPOName)|$($s.Script)|$($s.Parameters)"
            if ($seen.ContainsKey($id)) { $seen[$id]++; continue }
            $seen[$id] = 1
            [void]$seen
        }
    }
}
Write-Host "  User LOGON scripts seen in per-user GP state (de-duplicated across users)" -ForegroundColor White
if ($seen.Count -eq 0) { Write-Host "      (none)" -ForegroundColor DarkGray }
else {
    foreach ($k in $seen.Keys | Sort-Object) {
        $parts = $k -split '\|'
        Write-Host ("      {0,-45} {1} {2}   [{3} user(s)]" -f $parts[0], $parts[1], $parts[2], $seen[$k])
    }
}
if ($isAdmin) {
    Write-Host "  Tip: 'gpresult /h gp.html /scope:user' as a test user shows the full resultant logon-script list and script timing." -ForegroundColor DarkGray
}

Write-Sub "Local GPO script definitions (scripts.ini / psscripts.ini)"
$lgpo = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts'
foreach ($ini in 'scripts.ini', 'psscripts.ini') {
    $p = Join-Path $lgpo $ini
    if (Test-Path $p) {
        Write-Host "  $p" -ForegroundColor White
        Get-Content $p | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "      $_" }
    }
    else { Write-Host "  $p  (not present)" -ForegroundColor DarkGray }
}
$lgpoStartup = Join-Path $lgpo 'Startup'
if (Test-Path $lgpoStartup) {
    Write-Host "  Files in $lgpoStartup" -ForegroundColor White
    Get-ChildItem $lgpoStartup -File -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("      {0,-50} {1,10:N0} bytes  modified {2}" -f $_.Name, $_.Length, $_.LastWriteTime) }
}

Write-Section "RUN / RUNONCE KEYS, STARTUP FOLDERS, WINLOGON"

Write-Sub "Registry Run keys  (RunOnce entries dimmed; yellow = program file not found)"
Show-RunKeys -Keys @(
    @{ Label = 'HKLM Run';            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Label = 'HKLM Run (32-bit)';   Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
    @{ Label = 'HKLM Policy Run';     Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' },
    @{ Label = 'HKLM RunOnce';        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Label = 'HKLM RunOnce (32)';   Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Label = 'HKCU Run';            Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Label = 'HKCU RunOnce';        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
)

Write-Sub "Startup folders"
$startupFolders = @(@{ Label = 'All Users'; Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" })
$startupFolders += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    @{ Label = $_.Name; Path = (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
}
$sfRows = foreach ($f in $startupFolders) {
    if (-not (Test-Path $f.Path)) { continue }
    Get-ChildItem $f.Path -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
        $target = if ($_.Extension -eq '.lnk') { Get-ShortcutTarget $_.FullName } else { $_.FullName }
        [pscustomobject]@{ Folder = $f.Label; File = $_.Name; Modified = $_.LastWriteTime.ToString('dd/MM/yyyy HH:mm'); Target = $target }
    }
}
$sfRows = @($sfRows)
if ($sfRows.Count -gt 0) {
    $fw = [math]::Max(6, (@($sfRows | ForEach-Object { $_.Folder.Length }) | Measure-Object -Maximum).Maximum)
    $iw = [math]::Max(4, (@($sfRows | ForEach-Object { $_.File.Length })   | Measure-Object -Maximum).Maximum)
    $fmt = "  {0,-$fw}  {1,-$iw}  {2,-16}  {3}"
    Write-Host ($fmt -f 'Folder', 'File', 'Modified', 'Target') -ForegroundColor White
    Write-Host ($fmt -f ('-' * $fw), ('-' * $iw), '--------', '------') -ForegroundColor DarkGray
    foreach ($r in $sfRows) { Write-Host ($fmt -f $r.Folder, $r.File, $r.Modified, $r.Target) }
}
else { Write-Host "      (all startup folders empty)" -ForegroundColor DarkGray }

Write-Sub "Winlogon"
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
$wlDefaults = @{ Userinit = 'C:\Windows\system32\userinit.exe'; Shell = 'explorer.exe'; VMApplet = 'SystemPropertiesPerformance.exe /pagefile' }
foreach ($n in 'Userinit', 'Shell', 'VMApplet', 'AppSetup', 'GinaDLL') {
    if (-not $wl.$n) { continue }
    $val  = ([string]$wl.$n).TrimEnd(',').Trim()
    $note = ''
    if ($wlDefaults.ContainsKey($n)) {
        if ($val -ieq $wlDefaults[$n]) { $note = '(default)' } else { $note = '<-- NON-DEFAULT' }
    }
    $colour = if ($note -like '<--*') { 'Yellow' } else { 'Gray' }
    Write-Host ("  {0,-10} {1,-55} {2}" -f $n, $val, $note) -ForegroundColor $colour
}
$notify = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
if (Test-Path $notify) {
    Get-ChildItem $notify -ErrorAction SilentlyContinue | ForEach-Object {
        $d = Get-ItemProperty $_.PSPath
        Write-Host ("  {0,-10} {1,-55} {2}" -f 'Notify', $_.PSChildName, $d.DLLName) -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------------------------------------------
# 6. Active Setup (runs each StubPath once per user on first logon to a given VDA)
# ----------------------------------------------------------------------------------------------
Write-Section "ACTIVE SETUP COMPONENTS (each runs once per new user profile on this host; non-Microsoft in white)"

$asRows = foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
    if (-not (Test-Path $root)) { continue }
    foreach ($c in Get-ChildItem $root -ErrorAction SilentlyContinue) {
        $p = Get-ItemProperty $c.PSPath -ErrorAction SilentlyContinue
        if (-not $p.StubPath) { continue }                        # nothing to run
        if ($p.IsInstalled -eq 0) { continue }                    # explicitly disabled
        $name = if ($p.'(default)') { $p.'(default)' } elseif ($p.ComponentID) { $p.ComponentID } else { $c.PSChildName }
        [pscustomobject]@{
            Name    = [string]$name
            Version = [string]$p.Version
            Stub    = [string]$p.StubPath
            Bits    = if ($root -like '*WOW6432Node*') { '32' } else { '64' }
            MS      = ($p.StubPath -match '\\(Windows|system32|SysWOW64)\\' -or $p.StubPath -match '(?i)regsvr32|rundll32|unregmp2|ie4uinit|mscories|themeui|wmpnscfg|msiexec')
        }
    }
}
$asRows = @($asRows | Sort-Object MS, Name)
if ($asRows.Count -eq 0) { Write-Host "      (none with a StubPath)" -ForegroundColor DarkGray }
else {
    $nw = [math]::Max(4, [math]::Min(45, (@($asRows | ForEach-Object { $_.Name.Length }) | Measure-Object -Maximum).Maximum))
    $fmt = "  {0,-$nw}  {1,-12}  {2,-3}  {3}"
    Write-Host ($fmt -f 'Component', 'Version', 'Bit', 'StubPath (runs as the user at first logon)') -ForegroundColor White
    Write-Host ($fmt -f ('-' * $nw), '-------', '---', '--------') -ForegroundColor DarkGray
    foreach ($r in $asRows) {
        $n = $r.Name; if ($n.Length -gt $nw) { $n = $n.Substring(0, $nw - 1) + '~' }
        Write-Host ($fmt -f $n, $r.Version, $r.Bits, $r.Stub) -ForegroundColor $(if ($r.MS) { 'DarkGray' } else { 'White' })
    }
    Write-Host ''
    Write-Host "  $(@($asRows | Where-Object { -not $_.MS }).Count) non-Microsoft Active Setup entries. Each one runs synchronously during the first logon of every user on this VDA." -ForegroundColor DarkGray
}

# ----------------------------------------------------------------------------------------------
# 7. WMI permanent event subscriptions
# ----------------------------------------------------------------------------------------------
Write-Section "WMI PERMANENT EVENT SUBSCRIPTIONS (root\subscription)"
try {
    $filters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop
    $bindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop

    if (-not $bindings) { Write-Host "  (no bindings - nothing is subscribed)" -ForegroundColor DarkGray }
    foreach ($b in $bindings) {
        $fName = ($b.Filter   -replace '.*Name="([^"]+)".*', '$1')
        $cName = ($b.Consumer -replace '.*Name="([^"]+)".*', '$1')
        $f = $filters   | Where-Object Name -eq $fName
        $c = $consumers | Where-Object Name -eq $cName
        Write-Host ("  Binding: filter '{0}' -> consumer '{1}'" -f $fName, $cName) -ForegroundColor White
        if ($f) { Write-Host ("      Query   : {0}" -f $f.Query) }
        if ($c) {
            Write-Host ("      Type    : {0}" -f $c.CimClass.CimClassName)
            if ($c.CommandLineTemplate) { Write-Host ("      Command : {0}" -f $c.CommandLineTemplate) }
            if ($c.ScriptText)          { Write-Host ("      Script  : {0}" -f ($c.ScriptText -replace '\s+', ' ').Substring(0, [math]::Min(200, $c.ScriptText.Length))) }
            if ($c.ScriptFileName)      { Write-Host ("      ScriptFile: {0}" -f $c.ScriptFileName) }
        }
    }
}
catch { Write-Host "  Could not query root\subscription: $($_.Exception.Message)" -ForegroundColor Red }

# ----------------------------------------------------------------------------------------------
# 8. Auto-start services outside \Windows (AV / monitoring / management agents)
# ----------------------------------------------------------------------------------------------
Write-Section "AUTO-START SERVICES WITH BINARIES OUTSIDE \WINDOWS"
$svc = Get-CimInstance Win32_Service | Where-Object {
    $_.StartMode -like 'Auto*' -and $_.PathName -and ($_.PathName -notlike "*$env:SystemRoot*") -and ($_.PathName -notlike '*\Windows\*')
}
$svc | Sort-Object DisplayName |
    Select-Object @{n='Name';e={$_.Name}}, DisplayName, State, StartMode, StartName, PathName |
    Format-Table -AutoSize | Out-String -Width 220 | Write-Host

# ----------------------------------------------------------------------------------------------
# 9. Data Deduplication (only relevant if this host serves the share - normally absent on a VDA)
# ----------------------------------------------------------------------------------------------
Write-Section "DATA DEDUPLICATION"
if (Get-Command Get-DedupVolume -ErrorAction SilentlyContinue) {
    try {
        $dv = Get-DedupVolume -ErrorAction Stop
        if ($dv) {
            Write-Sub "Volumes"
            $dv | Select-Object Volume, Enabled, UsageType, MinimumFileAgeDays, SavedSpace, SavingsRate, OptimizedFilesCount |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            Write-Sub "Status"
            Get-DedupStatus | Select-Object Volume, LastOptimizationTime, LastOptimizationResult, LastGarbageCollectionTime,
                                            LastScrubbingTime, InPolicyFilesCount, OptimizedFilesCount |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            Write-Sub "Job schedule"
            Get-DedupSchedule | Select-Object Name, Type, Enabled, Days, Start, Duration, Priority, Memory, Cores |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            Write-Sub "Jobs currently running / queued"
            $jobs = Get-DedupJob -ErrorAction SilentlyContinue
            if ($jobs) { $jobs | Format-Table -AutoSize | Out-String -Width 220 | Write-Host } else { Write-Host "      (none)" -ForegroundColor DarkGray }
        }
        else { Write-Host "  Dedup feature installed but no volumes enabled." -ForegroundColor DarkGray }
    }
    catch { Write-Host "  Dedup query failed: $($_.Exception.Message)" -ForegroundColor Red }
}
else { Write-Host "  Data Deduplication cmdlets not present on this server." -ForegroundColor DarkGray }

# ----------------------------------------------------------------------------------------------
# 10. Microsoft Defender schedule
# ----------------------------------------------------------------------------------------------
Write-Section "MICROSOFT DEFENDER SCAN SCHEDULE"
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $dayNames = 'Every day', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Never'
        Write-Host ("      ScanParameters        : {0}" -f $(if ($mp.ScanParameters -eq 2) { 'Full' } else { 'Quick' }))
        Write-Host ("      ScanScheduleDay       : {0} ({1})" -f $mp.ScanScheduleDay, $dayNames[[int]$mp.ScanScheduleDay])
        Write-Host ("      ScanScheduleTime      : {0}" -f $mp.ScanScheduleTime)
        Write-Host ("      ScanScheduleQuickTime : {0}" -f $mp.ScanScheduleQuickScanTime)
        Write-Host ("      ScanOnlyIfIdle        : {0}" -f $mp.ScanOnlyIfIdleEnabled)
        Write-Host ("      Realtime disabled     : {0}" -f $mp.DisableRealtimeMonitoring)
        Write-Host ("      Exclusion paths       : {0}" -f ($mp.ExclusionPath -join '; '))
        Write-Host ("      Exclusion extensions  : {0}" -f ($mp.ExclusionExtension -join '; '))
        $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($st) {
            Write-Host ("      Last full scan        : {0}" -f $st.FullScanStartTime)
            Write-Host ("      Last quick scan       : {0}" -f $st.QuickScanStartTime)
        }
    }
    catch { Write-Host "  Defender query failed: $($_.Exception.Message)" -ForegroundColor Red }
}
else { Write-Host "  Defender cmdlets not present (third-party AV? see services section)." -ForegroundColor DarkGray }

Write-Host ''
Write-Host ('=' * 110) -ForegroundColor Cyan
Write-Host "  Done." -ForegroundColor Cyan
Write-Host ('=' * 110) -ForegroundColor Cyan
