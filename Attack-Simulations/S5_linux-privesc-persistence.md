# S5 - Linux privilege escalation and persistence

## Scenario

Simulated post-compromise privilege escalation and persistence on UBUNTU-SRV (10.10.10.40), performed locally. Authorized self-test; no remote attacker in this scenario.

Actions:
1. `useradd backdoor`
2. `usermod -aG sudo backdoor`
3. `chpasswd` for `backdoor`
4. Cron persistence via `/etc/cron.d/system-update` (fake callback to 10.10.10.50)
5. SUID backdoor: `chmod +s` on a copy of `/bin/bash` at `/tmp/rootbash`
6. `history -c`

## Objective

Check how auditd and FIM telemetry in Wazuh show a local privilege escalation, persistence and anti-forensics sequence.

## Scope

UBUNTU-SRV (10.10.10.40) only, local actions, inside the lab network 10.10.10.0/24.

## Time

2026-11-23, about 17:35 - 17:36.

## Expected detections

auditd command events for each action (Phase 5 auditd rules), FIM events for the changed files, and higher severity for privilege-sensitive actions.

## Detections observed

| Rule | Description | Level | Commands |
|---|---|---|---|
| 80792 | Generic "Audit: Command: ..." (for example "Audit: Command: /usr/sbin/usermod.") | 3 | useradd, usermod, chpasswd, chmod, tee |
| 80791 | Audit: Deleted: /etc/ | 3 | |

- 229 audit events in total in the window.
- `rule.groups:syscheck` returned 0 results: FIM did not cover `/tmp` or `/etc/cron.d`.

Ground truth, confirmed independently, shows the privilege escalation succeeded:
- `getent group sudo` showed `sudo:x:27:socadmin,backdoor`.
- `id backdoor` showed `groups=1001(backdoor),27(sudo)`.

## Missed or weak detections

Gaps (Phase 8 targets):
1. **Severity:** privilege-sensitive commands (`usermod ... sudo`, `chmod +s`) scored the same as routine sudo use. Everything was level 3, with no escalation.
2. **FIM scope:** `/tmp` and `/etc/cron.d` are not monitored, so the SUID backdoor and the cron persistence left no FIM trail.
3. **Usability:** `rule.description` shows only the command name, not the arguments. An analyst scanning descriptions would not see "sudo" or "backdoor" without opening `full_log` / the execve arguments.
4. **Anti-forensics:** no rule was observed for shell history clearing.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1136.001 | Create Account: Local Account |
| T1098.007 (or T1548.003) | Sudoers / group modification |
| T1053.003 | Scheduled Task/Job: Cron |
| T1548.001 | Setuid and Setgid (SUID binary) |
| T1070.003 | Clear Command History |

## Evidence

- [Screenshots/attack-evidence/S5_linux-privesc-audit-events-level3.png](../Screenshots/attack-evidence/S5_linux-privesc-audit-events-level3.png) - the 229 audit events, all level 3
- [Screenshots/attack-evidence/S5_linux-fim-gap-no-syscheck-results.png](../Screenshots/attack-evidence/S5_linux-fim-gap-no-syscheck-results.png) - empty `rule.groups:syscheck` search

## Lessons

The activity was logged, but it was not prioritised and partly invisible to FIM. Phase 8 fix (done): `<syscheck>` scope expanded and rules 100002-100004 added (level 12 sudoers/cron, level 10 `/etc/passwd` / `/etc/shadow`, level 7 `/tmp`), validated by 2 x level 12 rule 100002 alerts after touching `/etc/cron.d/test-persistence` (P8-01); see [phase8-detection-engineering.md](../Documentation/phase8-detection-engineering.md). The original Phase 8 plan was:
- Add `/etc/cron.d`, `/etc/cron.daily`, `/tmp` and `/usr/local/bin` to syscheck realtime monitoring. **Status:** done. Cron and `/tmp` monitoring via FIM path matching (rules 100002-100004); `/usr/local/bin` (with `/usr/bin` and `/usr/sbin`) added to the `<syscheck>` scope for SUID detection ([section 3](../Documentation/phase8-detection-engineering.md#3-suidsgid-privilege-escalation-detection-chmod-s5)).
- Add custom Wazuh local rules that raise severity when `usermod` / `gpasswd` target the sudo or wheel group, and when `chmod` sets the SUID bit. **Status:** SUID part: Phase 8 fix (done). Rule 100009 (level 12) fired on `chmod u+s` under `/usr/local/bin` (`rwxr-xr-x` → `rwsr-xr-x`) and did not fire on `chmod u-s`; it only matches `rws`, so SUID on a non-executable file (`rwS`) is not caught ([section 3](../Documentation/phase8-detection-engineering.md#3-suidsgid-privilege-escalation-detection-chmod-s5)). `usermod` / `gpasswd` part: Phase 8 fix (done). Rule 100008 (level 10) fired on a live `sudo usermod` group modification, identifying the command and acting uid; it escalates on any `usermod` / `gpasswd` run, not only ones targeting a privileged group, so the target group must be checked in the raw log ([section 5](../Documentation/phase8-detection-engineering.md#5-privilege-group-modification-detection-usermod--gpasswd-s5)).
- Consider a rule on `history -c` / `HISTFILE` tampering. **Status:** Phase 8 fix (done) for `.bash_history` file changes only. Rule 100010 (level 12) fired on modification (550) and deletion (553) of `.bash_history`, but fires on any change, including normal history growth. `history -c` and `HISTFILE` tampering themselves remain undetected (no filesystem or syscall trace) ([section 4](../Documentation/phase8-detection-engineering.md#4-command-history-tampering-detection-s5)).
