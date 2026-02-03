###################
#    Functions    #
###################

# Set-RegValueAndVerify
# Creates/overwrites a registry value, then reads it back and prints [OK]/[FAIL] to confirm it matches the expected value.
# Supports DWord, String, ExpandString, MultiString, QWord, and Binary.
# Example (String)
#Set-RegValueAndVerify -Path $profilesKey -Name "VolumeType" -Type "String" -Value "vhdx" | Out-Null

function Set-RegValueAndVerify {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet("DWord","String","ExpandString","MultiString","QWord","Binary")]
        [string]$Type,
        [Parameter(Mandatory)]$Value
    )

    try {
        # Create/update the value
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null

        # Read back
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name

        # Compare (handle MultiString arrays properly)
        $isMatch = $false
        if ($Type -eq "MultiString") {
            $expectedArr = @($Value)
            $actualArr   = @($actual)
            $isMatch     = (($expectedArr -join "`n") -eq ($actualArr -join "`n"))
        } elseif ($Type -in @("Binary")) {
            $expectedArr = @($Value)
            $actualArr   = @($actual)
            $isMatch     = (($expectedArr -join ",") -eq ($actualArr -join ","))
        } else {
            $isMatch = ($actual -eq $Value)
        }

        if ($isMatch) {
            Write-Host ("[OK]   {0}\{1} ({2}) = {3}" -f $Path, $Name, $Type, ($actual -join ",")) -ForegroundColor Green
            return $true
        } else {
            Write-Host ("[FAIL] {0}\{1} ({2}) expected '{3}' but found '{4}'" -f $Path, $Name, $Type, ($Value -join ","), ($actual -join ",")) -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host ("[FAIL] {0}\{1} - {2}" -f $Path, $Name, $_.Exception.Message) -ForegroundColor Red
        return $false
    }
}

##############################
#    Variables (Change Me)   #
##############################
# UNC path to the Azure Files share used for FSLogix profile containers (VHD/VHDX location).
$profileShare = "\\fslogix30012026.file.core.windows.net\fslogix"

##########################
#    App Configuration   #
##########################
Write-Host "Configuring FSLogix App"

New-Item -Path "HKLM:\SOFTWARE" -Name "FSLogix" -ErrorAction Ignore | Out-Null
New-Item -Path "HKLM:\SOFTWARE\FSLogix" -Name "Apps" -ErrorAction Ignore | Out-Null

$appsKey = "HKLM:\SOFTWARE\FSLogix\Apps"

if (Test-Path $appsKey) {
    Write-Host ("[OK]   Registry key exists: {0}" -f $appsKey) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] Registry key missing: {0}" -f $appsKey) -ForegroundColor Red
}

Set-RegValueAndVerify -Path $appsKey -Name "CleanupInvalidSessions" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $appsKey -Name "RoamRecycleBin" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $appsKey -Name "VHDCompactDisk" -Type "DWord" -Value 1 | Out-Null

################
#    Profile   #
################
Write-Host "Configuring FSLogix (Profiles)"

New-Item -Path "HKLM:\SOFTWARE" -Name "FSLogix" -ErrorAction Ignore | Out-Null
New-Item -Path "HKLM:\SOFTWARE\FSLogix" -Name "Profiles" -ErrorAction Ignore | Out-Null

$profilesKey = "HKLM:\SOFTWARE\FSLogix\Profiles"

if (Test-Path $profilesKey) {
    Write-Host ("[OK]   Registry key exists: {0}" -f $profilesKey) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] Registry key missing: {0}" -f $profilesKey) -ForegroundColor Red
}

Set-RegValueAndVerify -Path $profilesKey -Name "Enabled" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "VHDLocations" -Type "String" -Value $profileShare | Out-Null

Set-RegValueAndVerify -Path $profilesKey -Name "CleanOutNotifications" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "DeleteLocalProfileWhenVHDShouldApply" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "FlipFlopProfileDirectoryName" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "GroupPolicyState" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "IgnoreNonWVD" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "InstallAppxPackages" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "IsDynamic" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "KeepLocalDir" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "LockedRetryCount" -Type "DWord" -Value 12 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "LockedRetryInterval" -Type "DWord" -Value 5 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "NoProfileContainingFolder" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "OutlookCachedMode" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "PreventLoginWithFailure" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "PreventLoginWithTempProfile" -Type "DWord" -Value 1 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "ProfileType" -Type "DWord" -Value 3 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "ReAttachIntervalSeconds" -Type "DWord" -Value 10 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "ReAttachRetryCount" -Type "DWord" -Value 60 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "RebootOnUserLogoff" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "RoamIdentity" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "RoamSearch" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "SetTempToLocalPath" -Type "DWord" -Value 3 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "ShutdownOnUserLogoff" -Type "DWord" -Value 0 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "SizeInMBs" -Type "DWord" -Value 30000 | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "VolumeType" -Type "String" -Value "vhdx" | Out-Null
Set-RegValueAndVerify -Path $profilesKey -Name "VolumeWaitTimeMS" -Type "DWord" -Value 20000 | Out-Null

###############################
#  Entra Kerberos + CredKeys  #
###############################

# Enable Cloud Kerberos ticket retrieval (equivalent to the GPO / CSP)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" -Name "Parameters" -Force | Out-Null
$krbParamsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

if (Test-Path $krbParamsKey) {
    Write-Host ("[OK]   Registry key exists: {0}" -f $krbParamsKey) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] Registry key missing: {0}" -f $krbParamsKey) -ForegroundColor Red
}

Set-RegValueAndVerify -Path $krbParamsKey -Name "CloudKerberosTicketRetrievalEnabled" -Type "DWord" -Value 1 | Out-Null

# Ensure Credential Manager keys are taken from the currently loading profile (FSLogix roaming)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "AzureADAccount" -Force | Out-Null
$azureAdAccountKey = "HKLM:\SOFTWARE\Policies\Microsoft\AzureADAccount"

if (Test-Path $azureAdAccountKey) {
    Write-Host ("[OK]   Registry key exists: {0}" -f $azureAdAccountKey) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] Registry key missing: {0}" -f $azureAdAccountKey) -ForegroundColor Red
}

Set-RegValueAndVerify -Path $azureAdAccountKey -Name "LoadCredKeyFromProfile" -Type "DWord" -Value 1 | Out-Null

# Map .file.core.windows.net to the Entra ID Kerberos realm
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm" -Force | Out-Null
$hostToRealmKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\KERBEROS.MICROSOFTONLINE.COM"

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\KERBEROS.MICROSOFTONLINE.COM" -Force | Out-Null

if (Test-Path $hostToRealmKey) {
    Write-Host ("[OK]   Registry key exists: {0}" -f $hostToRealmKey) -ForegroundColor Green
} else {
    Write-Host ("[FAIL] Registry key missing: {0}" -f $hostToRealmKey) -ForegroundColor Red
}

Set-RegValueAndVerify -Path $hostToRealmKey -Name "SpnMappings" -Type "MultiString" -Value @(".file.core.windows.net") | Out-Null

Write-Host "Entra Kerberos enabled and Credential Manager profile binding configured."
Write-Host "Configuration Complete"