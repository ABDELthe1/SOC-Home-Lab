# Phase 8 - Detection engineering

Custom Wazuh rules and FIM changes that close two detection gaps found during the attack simulations. Both fixes were validated live in the lab.

| # | Gap | Source scenario | Fix | Validation |
|---|---|---|---|---|
| 1 | Linux FIM scope and severity | [S5](../Attack-Simulations/S5_linux-privesc-persistence.md) | Expanded `<syscheck>`, rules 100002-100004 | 2 x level 12 rule 100002 |
| 2 | Kerberos 4768 / 4771 not identified or correlated | [S4](../Attack-Simulations/S4_ad-enumeration-spray.md) / [S6](../Attack-Simulations/S6_incident-response-report.md) | Rules 100005-100007 | 5 x level 8 rule 100005, 1 x level 12 rule 100007 |

## 1. Linux FIM and severity gap (S5)

### Gap

In S5 the original `<syscheck>` configuration on UBUNTU-SRV only watched a test directory (`/home/socadmin/fim-test`). The SUID backdoor in `/tmp` and the cron persistence in `/etc/cron.d` left no FIM trail, and privilege-sensitive activity was scored at the same flat level 3 as routine activity.

### Fix

FIM was expanded to the system paths used for persistence and privilege escalation, and three local rules on SOC-Server raise the severity of FIM hits on those paths:

| Rule | Level | Paths | Purpose |
|---|---|---|---|
| 100002 | 12 | sudoers and cron paths | Persistence / privilege escalation via sudoers or cron |
| 100003 | 10 | `/etc/passwd`, `/etc/shadow` | Critical account file modified |
| 100004 | 7 | `/tmp/` | File written to `/tmp` (staged payloads) |

`<syscheck>` block from UBUNTU-SRV `/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <disabled>no</disabled>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/sudoers,/etc/crontab</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/sudoers.d,/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/var/spool/cron/crontabs</directories>
  <directories realtime="yes" check_all="yes" report_changes="no">/tmp</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/home/socadmin/fim-test</directories>
  <frequency>43200</frequency>
</syscheck>
```

Rules from SOC-Server `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,syscheck,linux_persistence,">

  <rule id="100002" level="12">
    <if_group>syscheck</if_group>
    <match>/etc/sudoers|/etc/sudoers.d|/etc/cron.d|/etc/crontab|/etc/cron.daily|/etc/cron.hourly|/var/spool/cron/crontabs</match>
    <description>Linux persistence: sudoers or cron file added/modified on $(agent.name)</description>
    <mitre>
      <id>T1053.003</id>
      <id>T1548.003</id>
    </mitre>
    <group>persistence,privilege_escalation,</group>
  </rule>

  <rule id="100003" level="10">
    <if_group>syscheck</if_group>
    <match>/etc/passwd|/etc/shadow</match>
    <description>Critical account file modified on $(agent.name): /etc/passwd or /etc/shadow</description>
    <mitre>
      <id>T1098.007</id>
      <id>T1136.001</id>
    </mitre>
    <group>persistence,privilege_escalation,</group>
  </rule>

  <rule id="100004" level="7">
    <if_group>syscheck</if_group>
    <match>/tmp/</match>
    <description>File written to /tmp on $(agent.name) - review for staged payloads</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>persistence,</group>
  </rule>

</group>
```

### Validation

Touching `/etc/cron.d/test-persistence` on UBUNTU-SRV produced two level 12 rule 100002 alerts ("Linux persistence: sudoers or cron file added/modified on UBUNTU-SRV").

Evidence: [Screenshots/attack-evidence/P8-01_linux-severity-fix-validated.png](../Screenshots/attack-evidence/P8-01_linux-severity-fix-validated.png)

## 2. Kerberos 4768 / 4771 gap (S4 / S6)

### Gap

Kerberos event IDs 4768 (TGT requested) and 4771 (Kerberos pre-authentication failed) were already caught by the generic rule 60104 (Windows audit failure, level 5). The real gap was not a total absence of alerting, but:
- no Kerberos-specific identification,
- no MITRE ATT&CK mapping,
- no correlation of repeated failures into a spray alert.

A Kerberos-native password spray would therefore appear only as undifferentiated level 5 audit failures, while the NTLM/SMB path already escalates to rule 60204 (level 10).

### Fix

| Rule | Level | Trigger | Purpose |
|---|---|---|---|
| 100005 | 8 | Rule 60104 with event ID 4771 | Kerberos pre-authentication failure |
| 100006 | 8 | Rule 60104 with event ID 4768 and non-zero status | Failed TGT request (possible invalid account enumeration) |
| 100007 | 12 | 5 events in group `kerberos_auth_failed` within 120 s, same source IP | Kerberos password spray; mirrors rule 60204 on the NTLM path |

Rules from SOC-Server `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,windows,kerberos,">

  <rule id="100005" level="8">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^4771$</field>
    <description>Kerberos pre-authentication failed for $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failed,kerberos_auth_failed,</group>
  </rule>

  <rule id="100006" level="8">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <field name="win.eventdata.status" negate="yes">^0x0$</field>
    <description>Kerberos TGT request failed for $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress) - possible invalid account enumeration</description>
    <mitre>
      <id>T1110.003</id>
      <id>T1589.002</id>
    </mitre>
    <group>authentication_failed,kerberos_auth_failed,</group>
  </rule>

  <rule id="100007" level="12" frequency="5" timeframe="120">
    <if_matched_group>kerberos_auth_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Kerberos password spray detected: multiple pre-authentication failures from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,kerberos_auth_failed,</group>
  </rule>

</group>
```

### Validation

6 kerbrute `passwordspray` attempts against Administrator from 10.10.10.50 (2026-11-24, 15:26:28 - 15:26:38):
- Attempts 1-4: level 8 rule 100005 ("Kerberos pre-authentication failed for Administrator from 10.10.10.50").
- Attempt 5: level 12 rule 100007 escalation ("Kerberos password spray detected: multiple pre-authentication failures from 10.10.10.50").
- Attempt 6: a further level 8 rule 100005 hit, after the escalation had already fired.

In total: 5 x level 8 rule 100005 and 1 x level 12 rule 100007, the same pattern the NTLM spray detection (rules 60122 / 60204) showed in S4.

Evidence: [Screenshots/attack-evidence/P8-02_kerberos-spray-detection-validated.png](../Screenshots/attack-evidence/P8-02_kerberos-spray-detection-validated.png)
