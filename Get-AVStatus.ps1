#Requires -Version 5.1
<#
.SYNOPSIS
    Reports the current antivirus posture of a Windows device, with a specific
    check for SentinelOne remnants and the state of Microsoft Defender.

.NOTES
    Run from an elevated PowerShell 5.1 session for complete results.
    The SecurityCenter2 WMI namespace only exists on client editions of Windows
    (10/11); on Windows Server that section will report "not available".
#>

[CmdletBinding()]
param()

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Label, [string]$Value, [string]$Colour = 'White')
    Write-Host ("  {0,-34} " -f $Label) -NoNewline
    Write-Host $Value -ForegroundColor $Colour
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Section "Device"
Write-Status "Computer name"  $env:COMPUTERNAME
Write-Status "OS"             (Get-CimInstance Win32_OperatingSystem).Caption
Write-Status "Running as admin" $isAdmin ($(if ($isAdmin) { 'Green' } else { 'Yellow' }))
Write-Status "Checked at"     (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

# ---------------------------------------------------------------------------
# 1. Windows Security Center view (what Windows itself believes is the AV)
# ---------------------------------------------------------------------------
Write-Section "Windows Security Center - registered AV products"

$scProducts = $null
try {
    $scProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
} catch {
    Write-Status "SecurityCenter2" "Not available on this OS (expected on Windows Server)" 'Yellow'
}

if ($scProducts) {
    foreach ($p in $scProducts) {
        $state    = [int]$p.productState
        $hex      = ('0x{0:X6}' -f $state)
        # Bit 12 of productState = real-time protection enabled; bit 4 = definitions out of date
        $enabled  = ($state -band 0x1000) -ne 0
        $outdated = ($state -band 0x10)   -ne 0

        Write-Host ""
        Write-Status "Product"           $p.displayName 'White'
        Write-Status "  Enabled"         $enabled   ($(if ($enabled)  { 'Green' } else { 'Red' }))
        Write-Status "  Definitions"     ($(if ($outdated) { 'OUT OF DATE' } else { 'Up to date' })) ($(if ($outdated) { 'Red' } else { 'Green' }))
        Write-Status "  productState"    "$state ($hex)"
        Write-Status "  Executable"      $p.pathToSignedProductExe
        Write-Status "  Last reported"   $p.timestamp
    }
} elseif ($null -ne $scProducts) {
    Write-Status "Registered AV products" "NONE - device is unprotected" 'Red'
}

# ---------------------------------------------------------------------------
# 2. SentinelOne - is anything left behind?
# ---------------------------------------------------------------------------
Write-Section "SentinelOne remnants"

$s1Found = $false

# Services (any Sentinel* service)
$s1Services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Sentinel*' }
if ($s1Services) {
    $s1Found = $true
    foreach ($svc in $s1Services) {
        $colour = if ($svc.Status -eq 'Running') { 'Red' } else { 'Yellow' }
        Write-Status "Service: $($svc.Name)" $svc.Status $colour
    }
} else {
    Write-Status "Services" "None found" 'Green'
}

# Processes
$s1Procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'Sentinel*' }
if ($s1Procs) {
    $s1Found = $true
    Write-Status "Processes" (($s1Procs | Select-Object -ExpandProperty ProcessName -Unique) -join ', ') 'Red'
} else {
    Write-Status "Processes" "None running" 'Green'
}

# Kernel drivers
$s1Drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Sentinel*' }
if ($s1Drivers) {
    $s1Found = $true
    foreach ($d in $s1Drivers) {
        Write-Status "Driver: $($d.Name)" "$($d.State) (Start: $($d.StartMode))" 'Yellow'
    }
} else {
    Write-Status "Drivers" "None found" 'Green'
}

# Install directory
$s1Dirs = @(
    "$env:ProgramFiles\SentinelOne",
    "${env:ProgramFiles(x86)}\SentinelOne",
    "$env:ProgramData\Sentinel"
) | Where-Object { $_ -and (Test-Path $_) }
if ($s1Dirs) {
    $s1Found = $true
    Write-Status "Folders present" ($s1Dirs -join '; ') 'Yellow'
} else {
    Write-Status "Folders" "None found" 'Green'
}

# Uninstall registry entries
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$s1Reg = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
         Where-Object { $_.DisplayName -like '*Sentinel*' }
if ($s1Reg) {
    $s1Found = $true
    foreach ($r in $s1Reg) {
        Write-Status "Uninstall entry" "$($r.DisplayName) $($r.DisplayVersion)" 'Yellow'
    }
} else {
    Write-Status "Uninstall registry entries" "None found" 'Green'
}

# sentinelctl status, if the binary still exists
$sentinelCtl = Get-ChildItem "$env:ProgramFiles\SentinelOne\Sentinel Agent*\SentinelCtl.exe" -ErrorAction SilentlyContinue |
               Select-Object -First 1
if ($sentinelCtl) {
    $s1Found = $true
    Write-Host ""
    Write-Host "  SentinelCtl.exe status output:" -ForegroundColor Yellow
    try {
        & $sentinelCtl.FullName status 2>&1 | ForEach-Object { Write-Host "    $_" }
    } catch {
        Write-Host "    Failed to run SentinelCtl: $_" -ForegroundColor Red
    }
}

Write-Host ""
if ($s1Found) {
    Write-Status "SentinelOne verdict" "REMNANTS DETECTED - see above" 'Red'
} else {
    Write-Status "SentinelOne verdict" "Fully removed" 'Green'
}

# ---------------------------------------------------------------------------
# 3. Microsoft Defender state
# ---------------------------------------------------------------------------
Write-Section "Microsoft Defender"

$mp = $null
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { Write-Status "Get-MpComputerStatus" "Failed: $($_.Exception.Message)" 'Yellow' }
} else {
    Write-Status "Defender module" "Not present on this device" 'Yellow'
}

if ($mp) {
    $bool = { param($v) if ($v) { 'Green' } else { 'Red' } }
    Write-Status "Running mode"              $mp.AMRunningMode ($(if ($mp.AMRunningMode -eq 'Normal') { 'Green' } else { 'Yellow' }))
    Write-Status "AM service enabled"        $mp.AMServiceEnabled        (& $bool $mp.AMServiceEnabled)
    Write-Status "Antivirus enabled"         $mp.AntivirusEnabled        (& $bool $mp.AntivirusEnabled)
    Write-Status "Real-time protection"      $mp.RealTimeProtectionEnabled (& $bool $mp.RealTimeProtectionEnabled)
    Write-Status "Behaviour monitoring"      $mp.BehaviorMonitorEnabled  (& $bool $mp.BehaviorMonitorEnabled)
    Write-Status "On-access protection"      $mp.OnAccessProtectionEnabled (& $bool $mp.OnAccessProtectionEnabled)
    Write-Status "Tamper protection"         $mp.IsTamperProtected       (& $bool $mp.IsTamperProtected)
    Write-Status "Engine version"            $mp.AMEngineVersion
    Write-Status "Signature version"         $mp.AntivirusSignatureVersion
    Write-Status "Signature age (days)"      $mp.AntivirusSignatureAge   ($(if ($mp.AntivirusSignatureAge -le 3) { 'Green' } else { 'Red' }))
    Write-Status "Signatures last updated"   $mp.AntivirusSignatureLastUpdated
    Write-Status "Last quick scan"           $mp.QuickScanEndTime
    Write-Status "Last full scan"            $mp.FullScanEndTime

    $wd = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($wd) { Write-Status "WinDefend service" "$($wd.Status) ($($wd.StartType))" ($(if ($wd.Status -eq 'Running') { 'Green' } else { 'Red' })) }
}

# ---------------------------------------------------------------------------
# 4. Any other third-party security software still installed
# ---------------------------------------------------------------------------
Write-Section "Other security software in Add/Remove Programs"

$avPattern = 'Sentinel|Defender|Sophos|CrowdStrike|Falcon|McAfee|Trellix|Symantec|Norton|Kaspersky|ESET|Bitdefender|Trend Micro|Webroot|Cylance|Carbon Black|Malwarebytes|Avast|AVG|Cortex|Palo Alto|Huntress|Elastic Agent'
$otherAV = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -match $avPattern } |
           Sort-Object DisplayName -Unique
if ($otherAV) {
    foreach ($a in $otherAV) {
        Write-Status $a.DisplayName "$($a.DisplayVersion)  (installed $($a.InstallDate))"
    }
} else {
    Write-Status "Security products" "None matched" 'Yellow'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section "Summary"

$activeAV = @()
if ($scProducts) { $activeAV += $scProducts | Where-Object { ($_.productState -band 0x1000) -ne 0 } | Select-Object -ExpandProperty displayName }
if ($mp -and $mp.RealTimeProtectionEnabled -and $mp.AMRunningMode -eq 'Normal' -and $activeAV -notcontains 'Windows Defender') { $activeAV += 'Windows Defender' }

if ($activeAV) {
    Write-Status "Active real-time AV" ($activeAV -join ', ') 'Green'
} else {
    Write-Status "Active real-time AV" "NONE DETECTED - device appears unprotected" 'Red'
}
Write-Status "SentinelOne" ($(if ($s1Found) { 'Remnants present' } else { 'Removed' })) ($(if ($s1Found) { 'Red' } else { 'Green' }))
Write-Host ""
