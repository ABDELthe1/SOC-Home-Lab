# S4 - AD enumeration and password spray

## Scenario

AD reconnaissance and password spraying from the Parrot attacker (10.10.10.50) against DC01 (10.10.10.10), domain `SOC-LAB.LOCAL`.

Tool: NetExec (`nxc`).

Reconnaissance:
- `nxc smb` enumeration confirmed DC01: Windows 10/Server 2019 build 17763, SMB signing enabled, Null Auth allowed on SMB.
- Anonymous SMB user enumeration returned no users.
- Anonymous LDAP bind was correctly rejected by AD ("operationsError, successful bind must be completed").

Password spray:
- 5 usernames (Administrator, socadmin, backdoor, admin, testuser) x 4 common passwords = 20 attempts via SMB/NTLM, with `--continue-on-success`.
- 0 valid credentials found.

## Objective

Check that AD reconnaissance and a password spray against the Domain Controller are detected in Wazuh.

## Scope

Lab network 10.10.10.0/24 only, authorized. Source: Parrot (10.10.10.50). Target: DC01 (10.10.10.10), domain `SOC-LAB.LOCAL`.

## Time

2026-11-24, about 14:35 - 14:36.

## Expected detections

Windows logon failure alerts on DC01, escalated by Wazuh's built-in frequency correlation, as in the SSH brute-force scenario ([S1](S1_ssh-bruteforce-hydra.md)).

## Detections observed

| Rule | Level | Description | Hits |
|---|---|---|---|
| 60122 | 5 | Logon Failure - Unknown user or bad password | 18 |
| 60204 | 10 | Multiple Windows Logon Failures | 2 |

- Rule 60122 events: `data.win.eventdata.ipAddress` 10.10.10.50, `authenticationPackageName` NTLM, `logonType` 3 (network), targeting Administrator, testuser, socadmin, backdoor and admin.
- Rule 60204 confirms that Wazuh's built-in frequency correlation detected the spray pattern (same mechanism as the SSH brute-force scenario).
- No account lockout (event ID 4740) was triggered: the attempt volume stayed under the default lockout threshold, consistent with realistic low-and-slow spray behaviour.

## Missed or weak detections

Gap (Phase 8 target): Kerberos failures detected only generically (rule 60104, level 5), with no Kerberos identification or spray correlation.
- Wazuh's default ruleset (`0580-win-security_rules.xml`, `0220-msauth_rules.xml`) has explicit coverage for event ID 4769 (TGS / service ticket, rules 60106 / 60131), but no Kerberos-specific rule for 4768 (TGT requested) or 4771 (Kerberos pre-authentication failed).
- These events were caught generically by rule 60104 (Windows audit failure, level 5), but without Kerberos-specific identification or spray correlation.
- A Kerberos-native password spray (rather than NTLM/SMB) would therefore surface only as undifferentiated level 5 audit failures, with no spray escalation, since 4771 is the primary signal for Kerberos pre-auth failures. The Phase 8 fix now adds this ([phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md)).
- Detection in this run relied entirely on the NTLM/SMB path (4625-equivalent, rules 60122 / 60204), not on Kerberos telemetry.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1087.002 | Account Discovery: Domain Account |
| T1110.003 | Brute Force: Password Spraying |
| T1021.002 | Remote Services: SMB/Windows Admin Shares (attempted access vector) |

## Evidence

- [Screenshots/attack-evidence/S4_ad-spray-rule60122-list-20hits.png](../Screenshots/attack-evidence/S4_ad-spray-rule60122-list-20hits.png) - the 18 rule 60122 hits
- [Screenshots/attack-evidence/S4_ad-spray-rule60204-escalation-detail.png](../Screenshots/attack-evidence/S4_ad-spray-rule60204-escalation-detail.png) - rule 60204 escalation detail

## Lessons

- The NTLM/SMB spray was detected and escalated out of the box.
- Phase 8 fix (done): custom local Wazuh rules 100005 (4771), 100006 (4768) and 100007 (frequency correlation, level 12) close the parity gap with the already-working NTLM detection path. Validated live with a kerbrute password spray: 5 x level 8 rule 100005 and 1 x level 12 rule 100007; rule 100006 was not triggered in that test. See [phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md).
