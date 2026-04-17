#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Apply CIS Benchmark Level 1 hardening to Windows Server 2019/2022.
.PARAMETER SkipFirewall
    Skip Windows Firewall configuration.
.PARAMETER SkipDefender
    Skip Windows Defender configuration.
.PARAMETER WhatIf
    Show what would be changed without applying.
.EXAMPLE
    .\Invoke-Hardening.ps1
    .\Invoke-Hardening.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $SkipFirewall,
    [switch] $SkipDefender
)

$ErrorActionPreference = 'Stop'
$report = [System.Collections.Generic.List[object]]::new()

function Set-RegistryValue {
    param($Path, $Name, $Value, $Type = 'DWord')
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        $script:report.Add([PSCustomObject]@{ Control = "$Path\$Name"; Value = $Value; Status = 'Applied' })
    }
}

function Write-Section { param($Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

# ── 1. Password Policy ─────────────────────────────────────────────────────────
Write-Section "Account Policies"
$passPolicy = @"
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 30
"@
$infPath = "$env:TEMP\pass_policy.inf"
$passPolicy | Out-File $infPath -Encoding Unicode
if ($PSCmdlet.ShouldProcess('Local Security Policy', 'Apply password policy')) {
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $infPath /quiet
    Write-Host "Password policy applied" -ForegroundColor Green
}

# ── 2. Disable SMBv1 ──────────────────────────────────────────────────────────
Write-Section "SMB Hardening"
if ($PSCmdlet.ShouldProcess('SMBv1', 'Disable')) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart -ErrorAction SilentlyContinue
    Write-Host "SMBv1 disabled" -ForegroundColor Green
}
if ($PSCmdlet.ShouldProcess('SMB Signing', 'Enable')) {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
    Write-Host "SMB signing required" -ForegroundColor Green
}

# ── 3. Registry — Security Options ────────────────────────────────────────────
Write-Section "Security Options (Registry)"

# UAC — prompt for admin
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
# No autologon
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '0' 'String'
# Disable LLMNR
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
# Disable NetBIOS node type
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NodeType' 2
# Restrict anonymous SAM
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1
# No LM hash
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
# NTLMv2 only
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
# Disable WDigest
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
# Disable Remote Registry
if ($PSCmdlet.ShouldProcess('RemoteRegistry service', 'Disable')) {
    Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
    Set-Service -Name RemoteRegistry -StartupType Disabled
    Write-Host "RemoteRegistry disabled" -ForegroundColor Green
}
# Disable Telnet
if ($PSCmdlet.ShouldProcess('TlntSvr service', 'Disable')) {
    Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue
}
# RDP — require NLA
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1

# ── 4. Windows Firewall ───────────────────────────────────────────────────────
if (-not $SkipFirewall) {
    Write-Section "Windows Firewall"
    if ($PSCmdlet.ShouldProcess('Firewall', 'Enable all profiles, block inbound')) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -LogAllowed False -LogBlocked True -LogMaxSizeKilobytes 16384
        Write-Host "Firewall enabled (block inbound by default)" -ForegroundColor Green
    }
}

# ── 5. Windows Defender ───────────────────────────────────────────────────────
if (-not $SkipDefender) {
    Write-Section "Windows Defender"
    if ($PSCmdlet.ShouldProcess('Defender', 'Enable real-time and cloud protection')) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -EnableNetworkProtection Enabled
        # Attack Surface Reduction rules
        Add-MpPreference -AttackSurfaceReductionRules_Ids @(
            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550', # Block executable content from email
            'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', # Block Office child processes
            '3B576869-A4EC-4529-8536-B80A7769E899'  # Block Office code injection
        ) -AttackSurfaceReductionRules_Actions Enabled
        Write-Host "Defender hardened" -ForegroundColor Green
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Section "Summary"
Write-Host "Controls applied: $($report.Count)" -ForegroundColor Green
Write-Host "Reboot required to apply all changes." -ForegroundColor Yellow
$report | Format-Table Control, Value, Status -AutoSize
