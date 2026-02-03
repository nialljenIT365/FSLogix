####################################
#  FSLogix Redirections Validation #
####################################
Write-Host "Validating FSLogix redirections.xml..."

$profilesKey = "HKLM:\SOFTWARE\FSLogix\Profiles"
$valueName   = "RedirXMLSourceFolder"
$fileName    = "redirections.xml"

# Track validation results for final object
$hasBom          = $null
$isWellFormedXml = $null
$expandedFolder  = $null
$expectedPath    = $null
$fileSizeBytes   = $null
$lastWriteTime   = $null

# Track latest copy attempt from FSLogix Profile log
$latestProfileLogPath   = $null
$lastCopyAttemptLine    = $null
$lastCopyResultLine     = $null
$lastCopySuccess        = $null

if (-not (Test-Path -LiteralPath $profilesKey)) {
    Write-Host ("[FAIL] FSLogix Profiles registry key not found: {0}" -f $profilesKey) -ForegroundColor Red
}

# Check if the value exists
$props = Get-ItemProperty -Path $profilesKey -ErrorAction SilentlyContinue
if (-not $props -or -not ($props.PSObject.Properties.Name -contains $valueName)) {
    Write-Host ("[FAIL] Registry value not found: {0}\{1}" -f $profilesKey, $valueName) -ForegroundColor Red
}

$redirFolder = (Get-ItemProperty -Path $profilesKey -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ([string]::IsNullOrWhiteSpace($redirFolder)) {
    Write-Host ("[FAIL] {0}\{1} exists but is empty." -f $profilesKey, $valueName) -ForegroundColor Red
} else {
    Write-Host ("[OK]   {0}\{1} = {2}" -f $profilesKey, $valueName, $redirFolder) -ForegroundColor Green

    # Expand any env vars (e.g. %ProgramFiles%) if present
    $expandedFolder = [Environment]::ExpandEnvironmentVariables($redirFolder)

    if ($expandedFolder -ne $redirFolder) {
        Write-Host ("[OK]   Expanded path: {0}" -f $expandedFolder) -ForegroundColor Green
    }

    $expectedPath = Join-Path -Path $expandedFolder -ChildPath $fileName
    Write-Host ("[INFO] Expected redirections.xml path: {0}" -f $expectedPath) -ForegroundColor Yellow
}

# Validate folder exists (with error detail for UNC/permissions issues)
$folderExists = $false
if (-not [string]::IsNullOrWhiteSpace($expandedFolder)) {
    try {
        $folderExists = Test-Path -LiteralPath $expandedFolder -ErrorAction Stop
    } catch {
        $folderExists = $false
        Write-Host ("[FAIL] Unable to access folder: {0} | {1}" -f $expandedFolder, $_.Exception.Message) -ForegroundColor Red
    }

    if ($folderExists) {
        Write-Host ("[OK]   Folder exists: {0}" -f $expandedFolder) -ForegroundColor Green
    } else {
        Write-Host ("[FAIL] Folder does not exist or is not accessible: {0}" -f $expandedFolder) -ForegroundColor Red
    }
}

# Validate file exists (with error detail for UNC/permissions issues)
$fileExists = $false
if (-not [string]::IsNullOrWhiteSpace($expectedPath)) {
    try {
        $fileExists = Test-Path -LiteralPath $expectedPath -ErrorAction Stop
    } catch {
        $fileExists = $false
        Write-Host ("[FAIL] Unable to access file path: {0} | {1}" -f $expectedPath, $_.Exception.Message) -ForegroundColor Red
    }

    if ($fileExists) {
        $fi = Get-Item -LiteralPath $expectedPath -ErrorAction SilentlyContinue
        Write-Host ("[OK]   redirections.xml found: {0}" -f $expectedPath) -ForegroundColor Green
        if ($fi) {
            $fileSizeBytes = $fi.Length
            $lastWriteTime = $fi.LastWriteTime
            Write-Host ("[OK]   Size: {0} bytes | LastWriteTime: {1}" -f $fileSizeBytes, $lastWriteTime) -ForegroundColor Green
        }

        # BOM check (true if BOM present)
        try {
            $bytes = [System.IO.File]::ReadAllBytes($expectedPath)
            if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
                $hasBom = $true
                Write-Host "[FAIL] File has UTF-8 BOM (EF BB BF)." -ForegroundColor Red
            } else {
                $hasBom = $false
                Write-Host "[OK]   File has no UTF-8 BOM." -ForegroundColor Green
            }
        } catch {
            $hasBom = $null
            Write-Host ("[FAIL] Unable to read file bytes for BOM check: {0} | {1}" -f $expectedPath, $_.Exception.Message) -ForegroundColor Red
        }

        # Well-formed XML check
        try {
            [void][xml](Get-Content -LiteralPath $expectedPath -Raw -ErrorAction Stop)
            $isWellFormedXml = $true
            Write-Host "[OK]   redirections.xml is well-formed XML." -ForegroundColor Green
        } catch {
            $isWellFormedXml = $false
            Write-Host ("[FAIL] redirections.xml is not valid XML: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }

    } else {
        Write-Host ("[FAIL] redirections.xml not found or not accessible at expected path: {0}" -f $expectedPath) -ForegroundColor Red
    }
}

#########################################################
#  FSLogix Profile Log - Last Redirections.xml Copy Try #
#########################################################
Write-Host "Checking latest FSLogix Profile log for Redirections.xml copy activity..."

$fslogixProfileLogRoot = "C:\ProgramData\FSLogix\Logs\Profile"

$latestLog = Get-ChildItem -LiteralPath $fslogixProfileLogRoot -Filter "Profile-*.log" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($latestLog) {
    $latestProfileLogPath = $latestLog.FullName
    Write-Host ("[OK]   Latest FSLogix Profile log: {0}" -f $latestProfileLogPath) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] No FSLogix Profile logs found under: {0}" -f $fslogixProfileLogRoot) -ForegroundColor Red
}

if ($latestLog) {
    $attemptPattern = 'Attempting to copy:\s*".*\\Redirections\.xml"\s*to:\s*".*\\Redirections\.xml"'
    $resultPattern  = 'Redirections\.xml copy success|Redirections\.xml copy failed'

    $lines = Get-Content -LiteralPath $latestProfileLogPath -ErrorAction SilentlyContinue

    if ($lines) {
        $attemptIdx = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match $attemptPattern) { $attemptIdx += $i }
        }

        if ($attemptIdx.Count -gt 0) {
            $start = $attemptIdx[-1]
            $end   = [Math]::Min($start + 25, $lines.Count - 1)

            # Capture the last attempt line
            $lastCopyAttemptLine = $lines[$start]

            # Capture copy result line (success/fail) near the attempt line
            $resultIdx = $null
            for ($j = $start; $j -le $end; $j++) {
                if ($lines[$j] -match $resultPattern) {
                    $resultIdx = $j
                    break
                }
            }

            if ($null -ne $resultIdx) {
                $lastCopyResultLine = $lines[$resultIdx]
                $lastCopySuccess    = ($lastCopyResultLine -match 'copy success')
            } else {
                $lastCopyResultLine = $null
                $lastCopySuccess    = $null
            }

            Write-Host "[INFO] Last Redirections.xml copy attempt (from log):" -ForegroundColor Yellow

            # Print up to 3 lines starting at $start to capture wrapping
            $wrapMax = [Math]::Min($start + 2, $lines.Count - 1)
            for ($k = $start; $k -le $wrapMax; $k++) {
                if ($lines[$k] -match 'Attempting to copy:' -or $lines[$k] -match '^\s*"[^"]+\\Redirections\.xml"\s*$' -or $lines[$k] -match '^\s*to:\s*$') {
                    Write-Host $lines[$k]
                }
            }

            if ($null -ne $lastCopyResultLine) {
                if ($lastCopySuccess -eq $true) {
                    Write-Host $lastCopyResultLine -ForegroundColor Green
                } else {
                    Write-Host $lastCopyResultLine -ForegroundColor Red
                }
            } else {
                Write-Host "[WARN] No copy success/failure line found after the last attempt." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN] No 'Attempting to copy ... Redirections.xml' entries found in the latest log." -ForegroundColor Yellow
        }
    } else {
        Write-Host ("[FAIL] Unable to read latest log content: {0}" -f $latestProfileLogPath) -ForegroundColor Red
    }
}

############################
# Emit object for logging  #
############################
[PSCustomObject]@{
    RedirectionsFolder        = $expandedFolder
    RedirectionsPath          = $expectedPath
    FolderExists              = $folderExists
    FileExists                = $fileExists
    FileSizeBytes             = $fileSizeBytes
    LastWriteTime             = $lastWriteTime
    IsWellFormedXml           = $isWellFormedXml
    Utf8BOMDetected           = $hasBom

    LatestProfileLogPath      = $latestProfileLogPath
    LastCopyAttemptLine       = $lastCopyAttemptLine
    LastCopyResultLine        = $lastCopyResultLine
    LastCopySuccess           = $lastCopySuccess
}