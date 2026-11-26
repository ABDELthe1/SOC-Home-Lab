# Phase 8 - Detection engineering

Custom Wazuh rules and FIM changes that close detection gaps found during the attack simulations. All fixes were validated live in the lab; known limitations are listed per section.

| # | Gap | Source scenario | Fix | Validation |
|---|---|---|---|---|
| 1 | Linux FIM scope and severity | [S5](../Attack-Simulations/S5_linux-privesc-persistence.md) | Expanded `<syscheck>`, rules 100002-100004 | 2 x level 12 rule 100002 |
| 2 | Kerberos 4768 / 4771 not identified or correlated | [S4](../Attack-Simulations/S4_ad-enumeration-spray.md) / [S6](../Attack-Simulations/S6_incident-response-report.md) | Rules 100005-100007 | 5 x level 8 rule 100005, 1 x level 12 rule 100007 |
| 3 | SUID bit set (`chmod u+s`) not detected | [S5](../Attack-Simulations/S5_linux-privesc-persistence.md) | FIM on binary directories, rule 100009 | Level 12 rule 100009 on `chmod u+s`; no 100009 on `chmod u-s` |
| 4 | Command history tampering not detected | [S5](../Attack-Simulations/S5_linux-privesc-persistence.md) | FIM on `.bash_history`, rule 100010 | Rule 100010 on modification (550) and deletion (553) |
| 5 | Privilege group modification (`usermod` / `gpasswd`) not detected | [S5](../Attack-Simulations/S5_linux-privesc-persistence.md) | Rule 100008 on execve audit events | Level 10 rule 100008 on a live `usermod` |

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

Before evidence: [Screenshots/wazuh-dashboard/P8-01a_ubuntu-auditd-flat-level3-before-tuning.png](../Screenshots/wazuh-dashboard/P8-01a_ubuntu-auditd-flat-level3-before-tuning.png) - Phase 5 (2026-11-20), before the root-execve auditd rule was restricted to `auid>=1000`: 1,596 audit events in 15 minutes, all rule 80792 at level 3, showing the flat level 3 baseline.

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

## 3. SUID/SGID privilege escalation detection (chmod) (S5)

### Gap

In S5, the SUID backdoor (`chmod +s` on a copy of `/bin/bash`) produced only a generic level 3 audit event, with no rule identifying the SUID change.

### Fix

FIM scope on UBUNTU-SRV extended to the binary directories (added to the `<syscheck>` block):

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/usr/local/bin,/usr/bin,/usr/sbin</directories>
```

Rule 100009 hooks off base rule 550 (Integrity checksum changed) and matches the literal `to 'rws` in `full_log`, i.e. an owner-execute-and-setuid permission string appearing as the new state after a syscheck-detected permission change.

Rule from SOC-Server `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,syscheck,linux_persistence,">
  <rule id="100009" level="12">
    <if_sid>550</if_sid>
    <match>to 'rws</match>
    <description>SUID bit set on monitored binary on $(agent.name): $(syscheck.path)</description>
    <mitre>
      <id>T1548.001</id>
    </mitre>
    <group>privilege_escalation,persistence,</group>
  </rule>
</group>
```

### Validation

Live test on UBUNTU-SRV:
- `chmod u+s` on a test binary under the newly expanded FIM scope (`/usr/local/bin`) fired rule 100009 at level 12 (`perm_before`: `rwxr-xr-x`, `perm_after`: `rwsr-xr-x`).
- Discrimination test: removing the SUID bit (`chmod u-s`) on the same file did **not** fire rule 100009 (only the generic rule 550 fired), confirming the rule distinguishes gaining SUID from losing it.

### Known limitations

1. Only the `rws` pattern (SUID + executable) is matched. A SUID bit set on a non-executable file renders as `rwS` and is not caught by this rule.
2. The `$(agent.name)` and `$(syscheck.path)` variables in the rule description do not interpolate (they render blank), the same category of cosmetic issue as rule 100008's `$(agent.name)`. The alert's raw `full_log` and syscheck JSON fields still contain the real path and permission data.
3. An auditd syscall watch (`-S chmod,fchmod,fchmodat`) was tried first. It was kernel-correct (verified with `ausearch`), but its events never reached Wazuh's alert layer (`alerts.json`), for reasons not fully root-caused (a link to the recurring "Too many fields for JSON decoder" errors is suspected, not confirmed). The FIM-based approach was adopted instead because it is empirically reliable.

## 4. Command history tampering detection (S5)

### Gap

In S5, `history -c` was run as an anti-forensics step and no rule was observed for shell history clearing.

### Fix

FIM scope on UBUNTU-SRV extended to the monitored user's `.bash_history` file (added to the `<syscheck>` block):

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/home/socadmin/.bash_history</directories>
```

Rule 100010 hooks off base rules 550 (modified) and 553 (deleted) and matches `.bash_history` in `full_log`.

Rule from SOC-Server `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,syscheck,linux_persistence,">
  <rule id="100010" level="12">
    <if_sid>550,553</if_sid>
    <match>.bash_history</match>
    <description>Possible command history tampering: .bash_history modified or deleted on $(agent.name)</description>
    <mitre>
      <id>T1070.003</id>
    </mitre>
    <group>defense_evasion,persistence,</group>
  </rule>
</group>
```

### Validation

Live tests on UBUNTU-SRV:
- Appending a line to `.bash_history` fired rule 100010 via the modified / 550 path (size 0 → 19, diff showing the added line).
- Deleting the file with `rm` fired rule 100010 via the deleted / 553 path (`full_log`: "File ... deleted", decoder `syscheck_deleted`).

### Known limitations

1. The rule fires on **any** `.bash_history` change, not specifically malicious clearing. Normal history growth from everyday shell use also triggers it; an analyst must check `size_before` / `size_after` / the diff in the raw alert to tell a truncation to zero (likely malicious) from normal growth.
2. `history -c` (the bash builtin that clears in-memory history without touching the file) and `unset HISTFILE` / `export HISTFILE=/dev/null` are **not** detected. Neither leaves a filesystem or syscall trace visible to the current tooling (FIM or the existing execve auditd rule). This is a documented gap: catching them would need shell-session-level auditing (for example TTY / keystroke logging), which is out of scope for the lab's current instrumentation.

## 5. Privilege group modification detection (usermod / gpasswd) (S5)

### Gap

No detection existed for privilege group modification commands (`usermod` / `gpasswd`) that add a user to sudo / wheel / admin. In S5, `usermod -aG sudo backdoor` produced only the generic level 3 rule 80792.

### Fix

Rule 100008 hooks off the generic execve audit rule 80792 and matches `audit.command` against `^usermod$|^gpasswd$`.

Rule from SOC-Server `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,audit,linux_persistence,">
  <rule id="100008" level="10">
    <if_sid>80792</if_sid>
    <field name="audit.command">^usermod$|^gpasswd$</field>
    <description>Privilege group modification command executed ($(audit.command)) by uid $(audit.uid) on $(agent.name) - review target group (sudo/wheel/admin)</description>
    <mitre>
      <id>T1098.007</id>
      <id>T1548.003</id>
    </mitre>
    <group>privilege_escalation,persistence,</group>
  </rule>
</group>
```

### Validation

Live test on UBUNTU-SRV: a group modification command run as socadmin via sudo (`sudo usermod -aG sudo testuser` or equivalent). Rule 100008 fired at level 10, correctly identifying the command (`usermod`) and the acting uid (0, root via sudo). Captured alert from `alerts.json` (timestamp `2026-11-26T17:36:42.136+0000`, excerpt):

```
"rule":{"level":10,"description":"Privilege group modification command executed (usermod) by uid 0 on  - review target group (sudo/wheel/admin)","id":"100008",...}
"full_log":"...comm=\"usermod\" exe=\"/usr/sbin/usermod\"...AUID=\"socadmin\" UID=\"root\"..."
```

Pre-fix evidence (S5, 2026-11-23, generic detection only):
- [Screenshots/attack-evidence/P8-03a_usermod-before-fix-events-list.png](../Screenshots/attack-evidence/P8-03a_usermod-before-fix-events-list.png) - 7 `usermod` events, all generic rule 80792 at level 3.
- [Screenshots/attack-evidence/P8-03b_usermod-before-fix-audit-detail.png](../Screenshots/attack-evidence/P8-03b_usermod-before-fix-audit-detail.png) - document details of one of them (rule 80792, level 3): an `exit -2` / `success no` sub-exec record (see limitation 3).
- [Screenshots/attack-evidence/P8-03c_usermod-before-fix-audit-fulllog.png](../Screenshots/attack-evidence/P8-03c_usermod-before-fix-audit-fulllog.png) - the same record's `full_log`, showing the `nscd` helper path and only the command name in `rule.description`.

### Known limitations

1. The rule escalates on **any** `usermod` / `gpasswd` invocation, not specifically ones that target a privileged group. The command-line arguments are not available in a clean structured Wazuh field for this decoder (only hex-encoded in `PROCTITLE` within `full_log`), so precise group-name matching was not attempted. The "review target group" wording in the description reflects that an analyst must check the raw log to see which group was targeted.
2. `$(agent.name)` in the description renders blank (visible as "on  -" in the alert above), the same cosmetic variable-interpolation issue seen in rules 100009 and 100010.
3. The audit records for a single `usermod` invocation can include several sub-exec entries, for example `exit="-2"` (ENOENT) records for the `nscd` / `sss_cache` cache-invalidation helpers that `usermod` tries internally. These are not failures of the detection or of the privilege action itself, only `usermod`'s internal NSS cache-flush attempts failing because those helper binaries are not installed on this minimal system.
