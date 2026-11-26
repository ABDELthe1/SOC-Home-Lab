# S7 - Incident response report: Linux privilege escalation and persistence on UBUNTU-SRV

Incident response write-up following the NIST SP 800-61 lifecycle. The S5 scenario ([S5_linux-privesc-persistence.md](S5_linux-privesc-persistence.md)) is treated as a real incident.

| Field | Value |
|---|---|
| Incident | Local privilege escalation, persistence and anti-forensics on a Linux server |
| Date / time | 2026-11-23, about 17:35 - 17:36 |
| Source | Local execution on UBUNTU-SRV (no remote attacker); cron callback pointed at 10.10.10.50 (fake) |
| Target | UBUNTU-SRV (10.10.10.40) |
| Attack vector | Local account creation, sudo group membership, cron, SUID binary, history clearing |
| Outcome | Privilege escalation succeeded: `backdoor` added to the sudo group |
| Highest alert (at the time) | Rules 80792 / 80791, level 3 (no escalation) |

All containment, eradication and recovery steps below are the documented response procedure for this lab. They were not executed as part of the S5 exercise.

**Evidence note:** the original incident (2026-11-23) was captured with the pre-Phase 8 monitoring only. The Phase 8 detections cited in this report were validated afterwards, each in its own test with test artefacts (see [phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md)). This report synthesises evidence captured at different points; it does not describe a single live re-run of the S5 chain with the Phase 8 rules in place.

## 1. Preparation

Telemetry and tooling in place before the incident (Phase 5):
- Wazuh agent registered on UBUNTU-SRV, forwarding to the Wazuh manager on SOC-Server (10.10.10.20).
- auditd rules ([Configuration/auditd/soc.rules](../Configuration/auditd/soc.rules)): watches on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` and `/etc/sudoers.d/` (key `audit-wazuh-w`), and root `execve` by logged-in users (`auid>=1000`, key `audit-wazuh-c`), decoded by the Wazuh built-in audit rules.
- Wazuh FIM in realtime on a single test directory, `/home/socadmin/fim-test`.

## 2. Detection and analysis

### What the analyst sees first

At the time of the incident: no high-severity signal. All activity appeared as generic level 3 audit events (rule 80792 "Audit: Command: ..." and rule 80791 "Audit: Deleted: /etc/"), 229 in the window, indistinguishable by severity from routine sudo use. `rule.groups:syscheck` returned 0 results.

### Alerts (at the time of the incident)

| Rule | Level | Description | Commands |
|---|---|---|---|
| 80792 | 3 | Audit: Command: ... (for example "Audit: Command: /usr/sbin/usermod.") | useradd, usermod, chpasswd, chmod, tee |
| 80791 | 3 | Audit: Deleted: /etc/ | |

- 229 audit events in total in the window.
- 0 FIM (syscheck) results: FIM did not cover `/tmp` or `/etc/cron.d`.

Ground truth, confirmed independently:
- `getent group sudo` showed `sudo:x:27:socadmin,backdoor`.
- `id backdoor` showed `groups=1001(backdoor),27(sudo)`.

### Attack chain and detection coverage

Steps in the order they were performed in S5, with the detection at the time and the Phase 8 rule that now covers each step:

| # | Action (S5) | At the time | Phase 8 rule | MITRE | Phase 8 validation |
|---|---|---|---|---|---|
| 1 | `useradd backdoor` (modifies `/etc/passwd`) | Rule 80792, level 3 | 100003, level 10 | T1136.001, T1098.007 | No validation alert recorded in the repo |
| 2 | `usermod -aG sudo backdoor` | Rule 80792, level 3 | 100008, level 10 | T1098.007, T1548.003 | Fired on a separate `sudo usermod` test (2026-11-26) |
| 3 | `chpasswd` for `backdoor` (modifies `/etc/shadow`) | Rule 80792, level 3 | 100003, level 10 | T1098.007, T1136.001 | No validation alert recorded in the repo |
| 4 | Cron persistence via `/etc/cron.d/system-update` | No FIM trail | 100002, level 12 | T1053.003, T1548.003 | 2 x level 12 on `/etc/cron.d/test-persistence` (P8-01) |
| 5 | `chmod +s` on a copy of `/bin/bash` at `/tmp/rootbash` | Rule 80792, level 3; no FIM trail | 100009, level 12 (SUID); 100004, level 7 (`/tmp` write) | T1548.001; T1105 | 100009 fired on `chmod u+s` of a test binary in `/usr/local/bin`, not in `/tmp`; 100004: no validation alert recorded in the repo |
| 6 | `history -c` | No rule | 100010, level 12 (`.bash_history` file changes only) | T1070.003 | Fired on `.bash_history` append and deletion; **`history -c` itself is not detected** |

### Timeline

Only timestamps recorded in the repo are used. The rows come from different captures, not one live incident:

| Time | Event | Source |
|---|---|---|
| 2026-11-23, ~17:35 - 17:36 | S5 attack chain executed; 229 level 3 audit events, 0 FIM results | S5 record |
| 2026-11-24, 15:16:01 and 15:16:21 | Phase 8 validation: 2 x rule 100002 (level 12) after touching `/etc/cron.d/test-persistence` | P8-01 screenshot |
| 2026-11-26, 17:36:42 UTC | Phase 8 validation: rule 100008 (level 10) on `usermod` run as socadmin via sudo | `alerts.json` excerpt, Phase 8 section 5 |
| Not recorded | Phase 8 validation: rule 100009 on `chmod u+s` (fired) and `chmod u-s` (did not fire) | Phase 8 section 3 |
| Not recorded | Phase 8 validation: rule 100010 on `.bash_history` modification and deletion | Phase 8 section 4 |

### Analysis

- **Pattern:** a complete local post-compromise chain: new account, privileged group membership, password set, scheduled persistence, a root SUID shell, and history clearing to cover tracks.
- **Impact:** the privilege escalation succeeded (`backdoor` in the sudo group), and a SUID copy of bash and a cron job were left in place.
- **Detection at the time:** every step was logged, but nothing was prioritised. All events were level 3, the descriptions showed only command names (not arguments such as "sudo" or "backdoor"), FIM saw nothing, and no rule covered history clearing.

MITRE ATT&CK: T1136.001 Create Account: Local Account, T1098.007 / T1548.003 sudoers and group modification, T1053.003 Scheduled Task/Job: Cron, T1548.001 Setuid and Setgid, T1105 Ingress Tool Transfer (staging in `/tmp`, rule 100004 mapping), T1070.003 Clear Command History.

## 3. Containment

Lab-appropriate steps:
1. Isolate UBUNTU-SRV from the lab network (keep console access through VMware), so the cron callback and any use of the new account are cut off.
2. Lock the `backdoor` account and remove it from the sudo group.
3. Preserve evidence: export the Wazuh alerts for UBUNTU-SRV in the incident window, `/var/log/audit/audit.log`, and copies (with hashes) of `/etc/cron.d/system-update` and `/tmp/rootbash`.

## 4. Eradication and recovery

1. Delete the `backdoor` account, `/etc/cron.d/system-update` and `/tmp/rootbash`.
2. Check for further persistence and privilege escalation: other SUID binaries, all cron locations, sudoers files, and members of privileged groups.
3. Confirm recovery: `getent group sudo` lists only the expected members, no unexpected SUID binaries remain, and the alert volume on UBUNTU-SRV is back to normal.
4. Reconnect UBUNTU-SRV to the lab network.

## 5. Post-incident activity and lessons learned

### What worked

Every action was logged by auditd and reached Wazuh (229 events), and the ground truth could be reconstructed from the logs.

### Gaps (at the time of the incident)

1. **Severity:** privilege-sensitive commands scored the same as routine sudo use (level 3, no escalation).
2. **FIM scope:** `/tmp` and `/etc/cron.d` were not monitored, so the SUID backdoor and the cron persistence left no FIM trail.
3. **Usability:** descriptions showed only command names, not arguments.
4. **Anti-forensics:** no rule for shell history clearing.

### Action items (Phase 8) - completed

One line per rule; details in [phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md):
- **Rule 100002** (level 12, sudoers / cron files): validated, 2 x level 12 on `/etc/cron.d/test-persistence` ([section 1](../Documentation/phase8-detection-engineering.md#1-linux-fim-and-severity-gap-s5)).
- **Rule 100003** (level 10, `/etc/passwd` / `/etc/shadow`): deployed; no validation alert recorded in the repo ([section 1](../Documentation/phase8-detection-engineering.md#1-linux-fim-and-severity-gap-s5)).
- **Rule 100004** (level 7, `/tmp` writes): deployed; no validation alert recorded in the repo ([section 1](../Documentation/phase8-detection-engineering.md#1-linux-fim-and-severity-gap-s5)).
- **Rule 100008** (level 10, `usermod` / `gpasswd`): validated on a live `usermod` ([section 5](../Documentation/phase8-detection-engineering.md#5-privilege-group-modification-detection-usermod--gpasswd-s5)).
- **Rule 100009** (level 12, SUID bit set): validated on `chmod u+s`, and correctly silent on `chmod u-s` ([section 3](../Documentation/phase8-detection-engineering.md#3-suidsgid-privilege-escalation-detection-chmod-s5)).
- **Rule 100010** (level 12, `.bash_history` modified or deleted): validated on append and deletion ([section 4](../Documentation/phase8-detection-engineering.md#4-command-history-tampering-detection-s5)).

### Known limitations (still open)

- **Rule 100008** escalates on any `usermod` / `gpasswd` invocation, not only ones targeting a privileged group; the target group must be checked in the raw log (arguments are only hex-encoded in `PROCTITLE`).
- **Rule 100009** only matches the `rws` pattern; SUID on a non-executable file (`rwS`) is not caught. It was validated in `/usr/local/bin`, not in `/tmp` where the S5 backdoor was placed.
- **Rule 100010** fires on any `.bash_history` change, including normal history growth. The in-memory `history -c` used in S5, and `HISTFILE` tampering, are still **not detected**.
- **Rules 100003 and 100004** have no recorded validation yet.
- The `$(agent.name)` variable renders blank in the descriptions of rules 100008, 100009 and 100010 (cosmetic; the raw alert fields are correct).

## Evidence

- [Screenshots/attack-evidence/S5_linux-privesc-audit-events-level3.png](../Screenshots/attack-evidence/S5_linux-privesc-audit-events-level3.png) - the 229 audit events at the time of the incident, all level 3
- [Screenshots/attack-evidence/S5_linux-fim-gap-no-syscheck-results.png](../Screenshots/attack-evidence/S5_linux-fim-gap-no-syscheck-results.png) - empty `rule.groups:syscheck` search at the time of the incident
- [Screenshots/attack-evidence/P8-01_linux-severity-fix-validated.png](../Screenshots/attack-evidence/P8-01_linux-severity-fix-validated.png) - Phase 8 validation of rule 100002
