# S6 - Incident response report: AD password spray against DC01

Incident response write-up following the NIST SP 800-61 lifecycle. The S4 scenario ([S4_ad-enumeration-spray.md](S4_ad-enumeration-spray.md)) is treated as a real incident.

| Field | Value |
|---|---|
| Incident | AD reconnaissance and password spray against the Domain Controller |
| Date / time | 2026-11-24, about 14:35 - 14:36 |
| Source | 10.10.10.50 (Parrot) |
| Target | DC01 (10.10.10.10), domain `SOC-LAB.LOCAL` |
| Attack vector | SMB/NTLM (network logon, logon type 3) |
| Outcome | 0 valid credentials, no account lockout |
| Highest alert | Wazuh rule 60204 "Multiple Windows Logon Failures", level 10 |

All containment, eradication and recovery steps below are the documented response procedure for this lab. They were not executed as part of the S4 exercise.

## 1. Preparation

Telemetry and tooling in place before the incident (Phases 4 and 5):
- Wazuh agent registered on DC01, forwarding Windows Security events to the Wazuh manager on SOC-Server (10.10.10.20).
- Windows audit policies on DC01 set with `auditpol`: Logon, Account Lockout, Credential Validation, User/Group Management, Process Creation and Kerberos.
- NTLM/SMB network logon failures logged on DC01 and decoded by Wazuh, including source IP, authentication package and logon type.
- Wazuh built-in frequency correlation for repeated Windows logon failures (rule 60204).
- Suricata on SOC-Server monitoring the lab network (Phase 6).

## 2. Detection and analysis

### What the analyst sees first

The first high-severity signal is rule **60204 "Multiple Windows Logon Failures" (level 10)**, which fired twice. Pivoting from it shows the underlying rule **60122 "Logon Failure - Unknown user or bad password" (level 5)** events.

### Alerts

| Rule | Level | Description | Hits |
|---|---|---|---|
| 60122 | 5 | Logon Failure - Unknown user or bad password | 18 |
| 60204 | 10 | Multiple Windows Logon Failures | 2 |

Key fields on the rule 60122 events:
- `data.win.eventdata.ipAddress`: 10.10.10.50 (single source)
- `authenticationPackageName`: NTLM
- `logonType`: 3 (network)
- Targeted accounts: Administrator, testuser, socadmin, backdoor, admin

### Timeline (2026-11-24)

| Time | Event |
|---|---|
| ~14:35 | SMB enumeration of DC01 from 10.10.10.50; anonymous SMB user enumeration returns no users; anonymous LDAP bind rejected by AD |
| ~14:35 - 14:36 | 20 NTLM authentication attempts against 5 accounts (4 passwords each); 18 x rule 60122 |
| ~14:35 - 14:36 | Rule 60204 fires twice: Wazuh's frequency correlation flags the pattern |

### Analysis

- **Pattern:** one source, several accounts, a few passwords each. This is a password spray, not a brute force against a single account.
- **Impact:** no successful authentication was found by the tool (0 valid credentials).
- **Lockout:** no account lockout (event ID 4740). The attempt volume stayed under the default lockout threshold, which is consistent with low-and-slow spray behaviour and means lockout alone would not have revealed the attack.
- **Reconnaissance exposure:** DC01 allows Null Auth on SMB, although anonymous user enumeration returned nothing and anonymous LDAP binds are rejected.

MITRE ATT&CK: T1087.002 Domain Account Discovery, T1110.003 Password Spraying, T1021.002 SMB/Windows Admin Shares (attempted access vector).

## 3. Containment

Lab-appropriate steps:
1. Block the source 10.10.10.50 from reaching DC01 (host firewall on DC01), or disconnect the attacker host from the lab network.
2. Confirm that no successful logon from 10.10.10.50 exists for the targeted accounts in the same window.
3. Increase monitoring on the five targeted accounts (Administrator, testuser, socadmin, backdoor, admin) until eradication is complete.
4. Preserve evidence: export the Wazuh alerts (rules 60122 / 60204) and the DC01 Security log for the incident window.

## 4. Eradication and recovery

1. Reset the passwords of the targeted accounts that exist in the domain, as a precaution even though no valid credentials were found.
2. Check for persistence on DC01: new or modified accounts and group memberships (especially privileged groups) and new scheduled tasks or services in the incident window.
3. Review the SMB Null Auth setting on DC01 to reduce the reconnaissance surface.
4. Remove the temporary source block once the source is confirmed as the authorized test host, and confirm normal authentication traffic and alert volume on DC01.

## 5. Post-incident activity and lessons learned

### What worked

The NTLM/SMB spray was detected out of the box: 18 individual failures (rule 60122) were correlated into a level 10 alert (rule 60204) without custom rules, the same mechanism that detected the SSH brute force in [S1](S1_ssh-bruteforce-hydra.md).

### Gap: generic-only Kerberos detection (no Kerberos identification or spray correlation)

- Wazuh's default ruleset (`0580-win-security_rules.xml`, `0220-msauth_rules.xml`) covers event ID 4769 (TGS / service ticket, rules 60106 / 60131), but has no Kerberos-specific rule for **4768** (TGT requested) or **4771** (Kerberos pre-authentication failed).
- These events were caught generically by rule 60104 (Windows audit failure, level 5) on DC01, but without Kerberos-specific identification or spray correlation.
- Detection in this incident relied entirely on the NTLM/SMB path. A Kerberos-native password spray would surface only as undifferentiated level 5 audit failures, with no spray escalation, since 4771 is the primary signal for Kerberos pre-authentication failures. The Phase 8 fix now adds this ([phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md)).

### Action item (Phase 8) - completed

Custom local Wazuh rules 100005 (4771), 100006 (4768) and 100007 (frequency correlation, level 12) were added, closing the parity gap with the NTLM detection path. Validated live with a kerbrute password spray against Administrator from 10.10.10.50: 5 x level 8 rule 100005 and 1 x level 12 rule 100007; rule 100006 was not triggered in that test. See [phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md).

## Evidence

- [Screenshots/attack-evidence/S6-01_incident-timeline.png](../Screenshots/attack-evidence/S6-01_incident-timeline.png) - incident timeline: Wazuh Threat Hunting dashboard filtered on rules 60204 / 60122 for 2026-11-24, all alerts from DC01
- [Screenshots/attack-evidence/S4_ad-spray-rule60122-list-20hits.png](../Screenshots/attack-evidence/S4_ad-spray-rule60122-list-20hits.png) - the 18 rule 60122 hits
- [Screenshots/attack-evidence/S4_ad-spray-rule60204-escalation-detail.png](../Screenshots/attack-evidence/S4_ad-spray-rule60204-escalation-detail.png) - rule 60204 escalation detail
- [Screenshots/attack-evidence/S6-01b_rule60122-count-18.png](../Screenshots/attack-evidence/S6-01b_rule60122-count-18.png) - rule 60122 alone: 18 alerts (backing evidence for the 18 + 2 = 20 count correction)
- [Screenshots/attack-evidence/S6-01c_rule60204-count-2.png](../Screenshots/attack-evidence/S6-01c_rule60204-count-2.png) - rule 60204 alone: 2 alerts (backing evidence for the 18 + 2 = 20 count correction)
