<#
.SYNOPSIS
    Enumerates all installed applications on a Windows device (32-bit and 64-bit)
    and prints a formatted inventory to the console.

.DESCRIPTION
    Reads the Uninstall registry keys from:
      - HKLM 64-bit  (HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)
      - HKLM 32-bit  (HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall)
      - HKCU 64-bit  (per-user installs)
      - HKCU 32-bit  (per-user installs)
    Entries without a DisplayName, or flagged as SystemComponent, are excluded.

.PARAMETER IncludeSystemComponents
    Include entries marked SystemComponent=1 (normally hidden from Programs & Features).

.PARAMETER Csv
    Output as CSV instead of a formatted table (handy for piping to a file).

.EXAMPLE
    .\Get-InstalledApps.ps1
    .\Get-InstalledApps.ps1 -IncludeSystemComponents
    .\Get-InstalledApps.ps1 -Csv > inventory.csv
#>

[CmdletBinding()]
param(
    [switch]$IncludeSystemComponents,
    [switch]$Csv
)

$registryPaths = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Arch = '64-bit'; Scope = 'Machine' },
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = '32-bit'; Scope = 'Machine' },
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Arch = '64-bit'; Scope = 'User'    },
    @{ Path = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = '32-bit'; Scope = 'User'    }
)

$apps = foreach ($entry in $registryPaths) {
    if (-not (Test-Path $entry.Path)) { continue }

    Get-ChildItem -Path $entry.Path -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue

        if ([string]::IsNullOrWhiteSpace($props.DisplayName)) { return }
        if (-not $IncludeSystemComponents -and $props.SystemComponent -eq 1) { return }

        # Normalise InstallDate (usually yyyyMMdd) to a readable date
        $installDate = $null
        if ($props.InstallDate -match '^\d{8}$') {
            try { $installDate = [datetime]::ParseExact($props.InstallDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') } catch {}
        }

        [PSCustomObject]@{
            Name         = $props.DisplayName.Trim()
            Version      = $props.DisplayVersion
            Publisher    = $props.Publisher
            Architecture = $entry.Arch
            Scope        = $entry.Scope
            InstallDate  = $installDate
            InstallPath  = $props.InstallLocation
            Uninstall    = $props.UninstallString
            RegistryKey  = $_.PSChildName
        }
    }
}

# De-duplicate (same name + version + arch can appear under multiple keys)
$apps = $apps |
    Sort-Object Name, Version, Architecture -Unique |
    Sort-Object Name

if ($Csv) {
    $apps | ConvertTo-Csv -NoTypeInformation
    return
}

$computer = $env:COMPUTERNAME
$os       = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$count64  = ($apps | Where-Object Architecture -eq '64-bit').Count
$count32  = ($apps | Where-Object Architecture -eq '32-bit').Count

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Installed Application Inventory" -ForegroundColor Cyan
Write-Host "  Device : $computer"
Write-Host "  OS     : $os"
Write-Host "  Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Total  : $($apps.Count) apps  ($count64 x 64-bit, $count32 x 32-bit)"
Write-Host "=================================================================" -ForegroundColor Cyan

$apps |
    Select-Object Name, Version, Publisher, Architecture, Scope, InstallDate |
    Format-Table -AutoSize -Wrap

Write-Host "Tip: run with -Csv to export, or -IncludeSystemComponents to show hidden entries." -ForegroundColor DarkGray
