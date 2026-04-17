#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Check Windows Server CIS Benchmark Level 1 compliance status.
    Outputs a PASS/FAIL report per control.
.EXAMPLE
    .\Test-CISCompliance.ps1
    .\Test-CISCompliance.ps1 | Export-Csv C:\Reports\cis-report.csv -NoTypeInformation
#>

$results = [System.Collections.Generic.List[object]]::new()
$pass = 0; $fail = 0

function Check {
    param($Control, $Description, [bool]$Passed)
    $status = if ($Passed) { 'PASS'; $script:pass++ } else { 'FAIL'; $script:fail++ }
    $color  = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1}" -f $status, $Description) -ForegroundColor $color
    $script:results.Add([PSCustomObject]@{
        Control     = $Control
        Description = $Description
        Status      = $status
    })
}

function Get-RegValue { param($Path, $Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

Write-Host "CIS Benchmark Compliance Check — $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME`n"

# SMBv1
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
Check '1.1' 'SMBv1 is disabled' (-not $smb1)

# SMB Signing
$smbSign = (Get-SmbServerConfiguration).RequireSecuritySignature
Check '1.2' 'SMB server signing is required' $smbSign

# UAC prompt
$uac = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
Check '2.1' 'UAC prompts for admin on secure desktop (value=2)' ($uac -eq 2)

# No LM hash
$noLM = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
Check '2.2' 'LM hash storage disabled' ($noLM -eq 1)

# NTLMv2 only
$ntlm = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Check '2.3' 'NTLMv2 only (LmCompatibilityLevel=5)' ($ntlm -ge 5)

# WDigest disabled
$wdigest = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
Check '2.4' 'WDigest authentication disabled' ($wdigest -eq 0)

# LLMNR disabled
$llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
Check '2.5' 'LLMNR disabled' ($llmnr -eq 0)

# RDP NLA
$nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
Check '3.1' 'RDP requires Network Level Authentication' ($nla -eq 1)

# Remote Registry
$rreg = (Get-Service RemoteRegistry -ErrorAction SilentlyContinue).StartType
Check '4.1' 'RemoteRegistry service is Disabled' ($rreg -eq 'Disabled')

# Firewall
$fw = Get-NetFirewallProfile -Profile Domain,Private,Public
$fwOk = ($fw | Where-Object { $_.Enabled -eq $true }).Count -eq 3
Check '5.1' 'Windows Firewall enabled on all profiles' $fwOk

# Defender real-time
$defender = (Get-MpPreference).DisableRealtimeMonitoring
Check '6.1' 'Windows Defender real-time protection enabled' ($defender -eq $false)

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " PASS: $pass  |  FAIL: $fail  |  Total: $($results.Count)"
$pct = [math]::Round(($pass / $results.Count) * 100, 1)
Write-Host " Compliance score: $pct%" -ForegroundColor $(if ($pct -ge 80) { 'Green' } else { 'Yellow' })
Write-Host "========================================"

$results
