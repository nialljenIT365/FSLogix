# Remediate-FSLogixRedirectionsXml.ps1
# Intune Remediations - Remediation
# Creates/repairs redirections.xml as UTF-8 without BOM

$RedirectionFileContent = @'
<?xml version="1.0" encoding="utf-8"?>
<FrxProfileFolderRedirection ExcludeCommonFolders="49">
  <Excludes>
    <Exclude Copy="0">AppData\Local\Microsoft\Edge\User Data\Default\Code Cache</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Edge\User Data\Default\GPUCache</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\ScriptCache</Exclude>
    <Exclude Copy="0">AppData\Local\Downloaded Installations</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Cache</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Cached Theme Image</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\GPUCache</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\JumpListIcons</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\JumpListIconsOld</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Local Storage</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Media Cache</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Pepper Data\Shockwave Flash\CacheWriteableAdobeRoot</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\SessionStorage</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\Storage</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\SyncData</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\SyncDataBackup</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\Default\WebApplications</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\EVWhitelist</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\PepperFlash</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\ShaderCache</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\SwReporter</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\SwiftShader</Exclude>
    <Exclude Copy="0">AppData\Local\Google\Chrome\User Data\WidevineCDM</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Edge\User Data\Default\Cache</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\MSOIdentityCRL\Tracing</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Office\16.0\Lync\Tracing</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\OneNote\16.0\Backup</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Teams\Current\Locales</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Teams\current\resources\locales</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Teams\Packages\SquirrelTemp</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Terminal Server Client\Cache</Exclude>
    <Exclude Copy="0">AppData\Local\Microsoft\Windows\WER</Exclude>
    <Exclude Copy="0">AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\WV2Profile_tfw\WebStorage</Exclude>
    <Exclude Copy="0">AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs</Exclude>
    <Exclude Copy="0">AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\PerfLogs</Exclude>
    <Exclude Copy="0">AppData\Local\SquirrelTemp</Exclude>
    <Exclude Copy="0">AppData\Roaming\Downloaded Installations</Exclude>
    <Exclude Copy="0">AppData\Roaming\Microsoft\Teams\Application Cache</Exclude>
    <Exclude Copy="0">AppData\Roaming\Microsoft\Teams\Cache</Exclude>
    <Exclude Copy="0">AppData\Roaming\Microsoft\Teams\Logs</Exclude>
    <Exclude Copy="0">AppData\Roaming\Microsoft\Teams\media-stack</Exclude>
    <Exclude Copy="0">AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage</Exclude>
  </Excludes>
</FrxProfileFolderRedirection>
'@

$RedirectionFilePath = "C:\Program Files\FSLogix\Redirections"
$RedirectionFileFullPath = Join-Path -Path $RedirectionFilePath -ChildPath "redirections.xml"

try {
    if ([string]::IsNullOrWhiteSpace($RedirectionFileContent)) {
        Write-Output "Remediation failed: XML content is empty."
        exit 1
    }

    # Validate XML first
    try {
        [void][xml]$RedirectionFileContent
    }
    catch {
        Write-Output "Remediation failed: XML content is not valid. $($_.Exception.Message)"
        exit 1
    }

    # Ensure folder exists
    if (-not (Test-Path -LiteralPath $RedirectionFilePath)) {
        New-Item -Path $RedirectionFilePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    # Write UTF-8 without BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($RedirectionFileFullPath, $RedirectionFileContent, $utf8NoBom)

    # Verify file exists
    if (-not (Test-Path -LiteralPath $RedirectionFileFullPath)) {
        Write-Output "Remediation failed: file was not created."
        exit 1
    }

    $fileInfo = Get-Item -LiteralPath $RedirectionFileFullPath -ErrorAction Stop
    if ($fileInfo.Length -le 0) {
        Write-Output "Remediation failed: file is empty."
        exit 1
    }

    # Verify BOM not present
    $bytes = [System.IO.File]::ReadAllBytes($RedirectionFileFullPath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        Write-Output "Remediation failed: file has UTF-8 BOM."
        exit 1
    }

    Write-Output "Remediation successful: redirections.xml written as UTF-8 without BOM."
    exit 0
}
catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
} 