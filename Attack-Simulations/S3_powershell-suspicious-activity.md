# S3 - Suspicious PowerShell activity

## Scenario

Simulated suspicious PowerShell activity on WIN-CLIENT (10.10.10.30), local execution. Authorized self-test.

Prerequisite configuration added for this scenario:
- PowerShell Script Block Logging (registry policy `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) and Transcription enabled.
- Wazuh agent localfile for `Microsoft-Windows-PowerShell/Operational` (`eventchannel`), alongside the existing Sysmon Event ID 1 coverage.

Actions:
1. Reconnaissance: `whoami /all`, `Get-LocalUser`, `Get-NetTCPConnection`, `systeminfo`.
2. Process discovery via spawned PowerShell processes.
3. Base64-encoded command execution: `Start-Process powershell -ArgumentList "-EncodedCommand <base64>"`.
4. Attempted download cradle: `(New-Object System.Net.WebClient).DownloadString` against the lab's own dashboard host. It failed with "Unable to connect" because the host listens on HTTPS, not HTTP; the connection attempt itself was still logged.

## Objective

Check that suspicious PowerShell behaviour (reconnaissance, obfuscated commands, download cradle) is detected in Wazuh from Sysmon and PowerShell logging.

## Scope

WIN-CLIENT (10.10.10.30) only, local execution, inside the lab network 10.10.10.0/24.

## Time

2026-11-23, about 17:58 - 18:03.

## Expected detections

Wazuh alerts from Sysmon process events and PowerShell Script Block Logging (Event ID 4104).

## Detections observed

All Wazuh built-in rules, no customization needed:

| Rule | Level | Description | Hits |
|---|---|---|---|
| 92057 | 12 | Powershell.exe spawned a powershell process which executed a base64 encoded command | 2 |
| 92201 | 9 | ...created a new scripting file under Windows Temp or User data folder | |
| 92066 | 4 | SecEdit.exe binary in a suspicious location launched by powershell.exe | |
| 91815 | 4 | Powershell executing process discovery | |
| 91816 | 4 | Powershell script querying system environment variables | |

- 21 hits in total across these rules in the 15-minute window.
- Rule 92057 captured the full `commandLine`, including the base64 blob, and the parent/child `powershell.exe` process chain.
- Both Sysmon (`commandLine`, parent/child process data) and Event ID 4104 (script block text) contributed telemetry.

## Missed or weak detections

None. No Phase 8 gap identified for this scenario.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1027 | Obfuscated Files or Information |
| T1082 | System Information Discovery |
| T1049 | System Network Connections Discovery |
| T1105 | Ingress Tool Transfer (attempted, failed) |

## Evidence

- [Screenshots/attack-evidence/S3_powershell-encoded-command-rule92057.png](../Screenshots/attack-evidence/S3_powershell-encoded-command-rule92057.png) - rule 92057 detail

## Lessons

- Strong out-of-the-box detection: Wazuh's built-in Windows/Sysmon ruleset identified the base64 obfuscation and scored it high severity (level 12) without custom rules.
- Clear contrast with the Linux auditd gaps in [S5](S5_linux-privesc-persistence.md), where everything was flat at level 3. Worth noting as a cross-platform comparison point in the final report.
