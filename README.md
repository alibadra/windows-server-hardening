# Windows Server Hardening

Automated security hardening for Windows Server 2019 / 2022, aligned with **CIS Benchmark Level 1 & 2**. One script to apply 80+ security controls.

## What's Included

| File | Description |
|------|-------------|
| `Invoke-Hardening.ps1` | Main script — applies all controls |
| `Backup-SecuritySettings.ps1` | Backup current settings before hardening |
| `Test-CISCompliance.ps1` | Check compliance status (pass/fail per control) |
| `configs/SecureBaseline.inf` | Security template for `secedit` |
| `configs/AuditPolicy.csv` | Advanced audit policy settings |

## Controls Applied

- **Account policies** — password complexity, length, lockout
- **User Rights Assignment** — least-privilege principle
- **Security Options** — UAC, NTLM, SMB signing, anonymous access
- **Windows Firewall** — block inbound by default, allow only needed ports
- **Services** — disable Telnet, FTP, Print Spooler (if not needed), LLMNR
- **SMBv1** — disabled
- **Remote Desktop** — NLA required, limited cipher suites
- **Windows Defender** — enable real-time, cloud protection, attack surface reduction
- **Audit Policy** — logon, privilege use, object access, policy change

## Quick Start

```powershell
# Run as Administrator
# 1. Backup first
.\Backup-SecuritySettings.ps1 -BackupPath C:\HardeningBackup

# 2. Check current compliance
.\Test-CISCompliance.ps1 | Export-Csv C:\Reports\baseline.csv

# 3. Apply hardening
.\Invoke-Hardening.ps1

# 4. Reboot
Restart-Computer -Confirm
```

> Always test in a non-production environment first!
