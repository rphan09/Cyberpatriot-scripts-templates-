# CyberPatriot Windows Hardening Script

This project hardens Windows 10, Windows 11 and Windows Server images for CyberPatriot practice rounds and competitions. Every setting is stored in JSON files in the `config` folder. Values can be changed there without editing the PowerShell code.

The project is based on [NuroC/CyberPatriotScript](https://github.com/NuroC/CyberPatriotScript). The original structure was kept, and the code was rewritten to fix its defects and to cover additional scored areas. The differences are listed in [Changes from the original project](#changes-from-the-original-project).

> **Warning.** This script changes security policy, users, services, firewall rules and the registry. It must be tested on practice images before it is used in a competition round. A virtual machine snapshot should be taken before each run whenever the environment allows it.

## Before running the script

1. **Answer every forensic question first.** Some steps remove users, move files and reset the hosts file. Those actions can destroy the evidence that a forensic question requires.
2. **Read the competition README.** Record the authorized users, the authorized administrators, the critical services, any required groups, shares and software.
3. **Fill in `config\competition.json`** with that information. The Users step is skipped when both user lists are empty, so that valid accounts are never removed by accident.
4. **Review the values in the other configuration files.** Some images require settings that differ from the defaults.

## Quick start

1. Copy the whole folder to the image, for example to `C:\CP`.
2. Edit `config\competition.json`.
3. Right-click `Start-Hardening.bat` and select **Run as administrator**. The batch file unblocks the downloaded files and starts PowerShell with a process-level execution policy of Bypass.

The script can also be started from an elevated PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Get-ChildItem -Recurse | Unblock-File
.\Run-Hardening.ps1 -DryRun          # Show every change without making it
.\Run-Hardening.ps1                  # Apply all enabled steps
.\Run-Hardening.ps1 -Only Firewall,Services
.\Run-Hardening.ps1 -Skip Files,Software
.\Run-Hardening.ps1 -Force           # No confirmation prompts
```

A dry run should always be performed first. The dry run prints every planned change in cyan and writes it to the log.

## Parameters

| Parameter | Purpose |
|---|---|
| `-DryRun` | Logs every change that would be made. Nothing is changed. |
| `-Only <steps>` | Runs only the named steps. |
| `-Skip <steps>` | Skips the named steps. |
| `-Force` | Removes confirmation prompts. User removal, share removal and task disabling then run without asking. |
| `-ConfigPath <folder>` | Uses a different configuration folder, for example one folder per image. |
| `-OutputPath <folder>` | Changes the folder for logs, backups and reports. The default is `C:\CP-Hardening\<date-time>`. |

## Configuration files

All numbers and lists are in the `config` folder. Keys that begin with an underscore (`_`) are explanations and are ignored by the script.

| File | Contents |
|---|---|
| `competition.json` | Information from the competition README: authorized users and administrators, critical services, required groups, shares and software, and an optional default password. **This file must be edited for every image.** |
| `security-policy.json` | Password policy, account lockout policy, legacy audit categories and user rights assignment. |
| `audit-policy.json` | Advanced audit policy subcategories. |
| `registry.json` | Registry-based settings grouped by category: UAC, logon, authentication, SMB, AutoPlay, Remote Desktop, Remote Assistance, SmartScreen, network, Windows Installer, PowerShell logging, screen saver, Defender policy, Windows Update policy, Chrome and Edge. |
| `services.json` | Services to disable and services that must keep running. |
| `firewall.json` | Built-in firewall rule groups to disable, and ports to block. |
| `prohibited.json` | Prohibited programs, Store apps, executables, file extensions and file name patterns. |
| `critical-services.json` | Definitions of the critical service tags and the services, ports and firewall groups that belong to each one. |
| `settings.json` | Options for each step, and the list of steps that run by default. |

### Changing a value

The default values follow current CIS Benchmark and Microsoft Security Baseline recommendations where those recommendations are compatible with typical CyberPatriot scoring. Some recommendations change between Windows releases, so the values are expected to be adjusted over time.

Example: to change the maximum password age to 90 days and the lockout threshold to 10 attempts, edit `config\security-policy.json`:

```json
"MaximumPasswordAge": 90,
"LockoutBadCount": 10,
```

Example: to change the screen saver timeout to 5 minutes, edit the `ScreenSaver` category in `config\registry.json`:

```json
{ "path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", "name": "ScreenSaveTimeOut", "type": "String", "value": "300", ... }
```

Example: to keep the Print Spooler running, add `"Printing"` to `criticalServices` in `config\competition.json`. The service, its firewall group and the printers are then left in place.

The script checks some values before applying them:

- `MinimumPasswordAge` must be lower than `MaximumPasswordAge`.
- `ResetLockoutCount` is reduced to `LockoutDuration` when it is larger.
- A `MinimumPasswordLength` above 14 also enables the "Relax minimum password length limits" setting.

### Critical services

The tags `RDP`, `SSH`, `FTP`, `HTTP`, `SMB`, `DNS`, `Printing`, `WinRM`, `Telnet`, `SNMP` and `VNC` are defined in `critical-services.json`. When a tag is listed in `competition.json`, the following rules apply:

- The services that belong to the tag are set to Automatic and started. They are never disabled.
- The tag's ports are allowed inbound, and its built-in firewall groups are enabled.
- Every item in the other files that names the tag in `skipIfCritical` is skipped. Every item that names it in `onlyIfCritical` is applied. For example, Network Level Authentication for Remote Desktop is enforced only when RDP is critical.

New tags can be added to `critical-services.json` and then referenced in the other files.

## Steps

The steps run in the order below. Each step can be turned off in `settings.json` under `steps`.

| Step | Action |
|---|---|
| Backup | Exports the security policy, audit policy, firewall policy, service list, users, group membership, selected registry keys and the hosts file. |
| SecurityPolicy | Applies password policy, lockout policy, legacy audit categories and user rights assignment with `secedit`. |
| AuditPolicy | Applies advanced audit subcategories with `auditpol`. |
| Users | Removes or disables unauthorized users. Removes unauthorized administrators from the Administrators group and adds missing ones. Sets passwords, clears "password never expires" and requires passwords. Disables Guest and the built-in Administrator. Creates required groups. Reports members of privileged groups. |
| Registry | Applies every enabled category in `registry.json`. |
| Firewall | Enables all profiles, sets default actions and logging, disables unneeded rule groups, adds block rules and opens ports for critical services. The step can be run repeatedly without creating duplicate rules. |
| Printers | Removes printers unless Printing is critical. This step runs before Services because Services may stop the Print Spooler. |
| Shares | Removes non-default SMB shares that are not listed as required. Reports shares open to Everyone, Guests or anonymous users. |
| Services | Disables insecure services and makes sure security services are running. |
| Features | Removes SMBv1, Telnet Client, TFTP, PowerShell 2.0 and other optional features. |
| Defender | Turns on real-time, behavior, cloud and PUA protection. Reports and removes exclusions. Updates signatures and starts a quick scan. |
| WindowsUpdate | Re-enables the update services and starts an update scan. |
| Tasks | Disables (does not delete) tasks in configured folders. Reports all non-Microsoft tasks and disables those that match suspicious command patterns, after confirmation. |
| SSH | Runs only when SSH is critical. Hardens `sshd_config` and restarts `sshd`. |
| Browsers | Writes a Firefox `policies.json`. Chrome and Edge policies are applied by the Registry step. |
| ServerRoles | Disables DNS zone transfers, enforces secure dynamic updates and cache pollution protection, and disables IIS directory browsing when those roles are present. |
| Hosts | Reports active hosts file entries and resets the file by default. |
| Persistence | Report only. Run keys, Startup folders, Winlogon values, AppInit_DLLs, Image File Execution Options debuggers, replaced accessibility programs, services outside the Windows folder, WMI subscriptions and listening ports. |
| Software | Reports prohibited programs, Store apps and hacking-tool executables. Uninstalling is optional and off by default. |
| Files | Reports media files, password lists and other prohibited files. Files can optionally be moved to a quarantine folder. Files are never deleted. |

## Output

Each run creates a folder such as `C:\CP-Hardening\20261115-140501` that contains:

- `hardening.log`: every action, with CHANGE, ERROR, WARN and REPORT entries.
- `transcript.txt`: the full PowerShell transcript.
- `backup\`: the state of the machine before the run.
- `reports\`: CSV files that require manual review, such as `prohibited-files.csv`, `prohibited-software.csv`, `autostart-entries.csv` and `backdoor-checks.csv`.

The reports are an important part of the result. Several scored items, such as prohibited files, unwanted software and backdoors, require a decision that a script cannot make safely.

## Restoring a backup

The files in the `backup` folder can be restored from an elevated prompt:

```powershell
secedit /configure /db C:\Windows\Temp\restore.sdb /cfg .\backup\secpol.inf
auditpol /restore /file:.\backup\auditpol.csv
netsh advfirewall import .\backup\firewall.wfw
reg import .\backup\registry-1.reg     # Repeat for each .reg file
```

Services and users must be restored manually with the help of `services.csv`, `users.csv` and `groups.csv`.

## Not included: Local Group Policy

**This script does not configure Local Group Policy.** It does not edit the Local Group Policy Object that is shown in the Local Group Policy Editor (`gpedit.msc`), and it does not create or change domain Group Policy Objects.

The following consequences apply:

- **Administrative Templates are not written to the policy file.** Several values in `registry.json` are stored under `HKLM\SOFTWARE\Policies` and `HKCU\Software\Policies`, which are the registry locations that Group Policy uses. Windows applies these values. However, they are written directly to the registry and not to `registry.pol`, so `gpedit.msc` still shows those settings as "Not configured".
- **Group Policy can overwrite these values.** A later `gpupdate /force`, a domain Group Policy Object or a change made in `gpedit.msc` can replace the values set by this script.
- **Domain policy is not changed.** On a domain controller, or on a member of a domain, the domain password policy, audit policy and user rights are controlled by Group Policy Objects in the Group Policy Management Console (`gpmc.msc`). This script changes only local settings. User rights assignment is skipped entirely on domain controllers.
- **Some scoring checks read Group Policy.** If a scored item is checked through the Local Group Policy Object, it must be set in `gpedit.msc` manually, or applied with Microsoft's `LGPO.exe` tool from the Security Compliance Toolkit.

The settings applied by `secedit` (password policy, lockout policy, audit categories and user rights assignment) are part of the local security policy. They are shown correctly in the Local Security Policy console (`secpol.msc`) and in `gpedit.msc` under *Computer Configuration > Windows Settings > Security Settings*.

## Other limitations

- Forensic questions must be answered manually.
- Domain users and groups in Active Directory are not managed. On a domain controller the Users step is skipped.
- The screen saver settings apply only to the account that runs the script.
- Third-party applications are not updated. Programs listed as required in the README, such as Firefox or Notepad++, must be updated manually.
- Windows Update is started, but installation must be monitored in Settings.
- Application-specific hardening other than the Firefox, Chrome, Edge, OpenSSH, IIS and DNS settings listed above is not included. Examples are FileZilla Server, Apache, MySQL and Samba-compatible software.
- Subcategory names in `audit-policy.json` and firewall group names in `firewall.json` are the English names. Images in other languages require translated names.
- Some settings, such as SMB driver changes and LSA protection, take effect only after a restart.

## Changes from the original project

| Area | Original behavior | Behavior in this project |
|---|---|---|
| Services | The module exported `Disable-DefaultServices`, a function that did not exist. The call to `disableUnsecureServices` therefore failed, and no services were changed. | The step works and uses a curated list in `services.json`. |
| Services | Disabled about 150 services, including Plug and Play, Netlogon, Windows Time and Remote Desktop, regardless of the README. Set the Print Spooler to Automatic. | Services that belong to a critical service are never disabled. Netlogon, Plug and Play and Windows Time are not disabled. The Print Spooler is disabled unless Printing is critical. |
| Services | Used wildcard names with `Set-Service`, which does not accept them. | Wildcards are resolved with `Get-Service` first. A registry fallback is used for services that reject `Set-Service`. |
| Printers | Listed in the README but not implemented. | Implemented. |
| Scheduled tasks | Deleted whole task folders with `Unregister-ScheduledTask`, which stopped for a confirmation prompt at each call. Did not inspect tasks created by attackers. | Tasks are disabled rather than deleted. All non-Microsoft tasks are reported, and suspicious ones are disabled after confirmation. |
| Firewall | Disabled every existing rule first. Created duplicate rules on every run. Used `-LocalPort` for outbound rules, so most outbound blocks had no effect. Blocked all ICMP. | Existing rules are kept, and only listed groups are disabled. Rules created by the script are removed and recreated on each run. Outbound rules use `-RemotePort`. Ping blocking is optional. |
| Firewall | Set `AllowLocalFirewallRules False` on the Public profile, which can prevent local rules from taking effect. | Removed. |
| SSH | Started `sshd` and opened port 22 on every image, while the firewall module blocked port 22. Did not change `sshd_config`. | SSH is configured only when it is critical, and `sshd_config` is hardened. Otherwise `sshd` is disabled. |
| Security policy | `MaximumPasswordAge` was 90 in the configuration file but 60 in the README. The audit values were documented as Success but set to Success and Failure. Values were not validated. | Values are documented beside each setting and validated before use. The built-in Administrator is not disabled while it is the account in use. |
| Security policy | Only System Access and Event Audit were set. | User rights assignment, advanced audit policy and security options (through `registry.json`) are also set. |
| General | No administrator check, no backups, no log file, no dry run, relative paths only. | Administrator check, backups, log file, transcript, dry run, `-Only` and `-Skip`, and paths that work from any folder. |

The following areas were not covered by the original project and have been added: users and groups, registry hardening, Defender, Windows Update, optional features, SMB shares, hosts file, browser policies, server roles, persistence checks, prohibited software and prohibited files.

## Credits

Based on [NuroC/CyberPatriotScript](https://github.com/NuroC/CyberPatriotScript). The original repository does not include a license.
