# S1 - SSH brute force (Hydra)

## Scenario

SSH brute-force password guessing from the Parrot attacker (10.10.10.50) against UBUNTU-SRV (10.10.10.40).

Tool: Hydra v9.5, 4 usernames x 8 passwords (32 combinations), `-t 4`.

Result: Hydra found 0 valid credentials.

## Objective

Check that repeated SSH password guessing is detected and escalated to a brute-force alert in Wazuh.

## Scope

Lab network 10.10.10.0/24 only, authorized. Source: Parrot (10.10.10.50). Target: UBUNTU-SRV (10.10.10.40).

## Time

2026-11-23, 17:27:59 - 17:28:24.

## Expected detections

Individual sshd failures in Wazuh, escalated by Wazuh's built-in frequency rule after 8 failed attempts from the same source within its time window.

## Detections observed

Individual failures:

| Rule | Description |
|---|---|
| 5760 | sshd: authentication failed |
| 5710 | sshd: attempt to login using a non-existent user |

Escalation:

| Rule | Description | Level | Source | Dest user | rule.frequency |
|---|---|---|---|---|---|
| 5712 | sshd: brute force trying to get access to the system. Non existent user. | 10 | 10.10.10.50 | admin | 8 |
| 5763 | sshd: brute force trying to get access to the system. Authentication failed. | 10 | 10.10.10.50 | socadmin / root | 8 |

Total in the 15-minute window: 46 sshd events (45 failures, 1 unrelated legitimate success). The success is rule 5715 at 17:02:15, from an earlier manual test, not from Hydra.

Suricata cross-check: ET SCAN Potential SSH Scan (SID 2001219) also fired on the same connections.

## Missed or weak detections

None. Clean detection, no Phase 8 gap: Wazuh correctly escalated from raw failures to a brute-force alert without custom rules.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |

## Evidence

- [Screenshots/attack-evidence/S1_ssh-bruteforce-rule5712-nonexistent-user.png](../Screenshots/attack-evidence/S1_ssh-bruteforce-rule5712-nonexistent-user.png)
- [Screenshots/attack-evidence/S1_ssh-bruteforce-rule5763-authentication-failed.png](../Screenshots/attack-evidence/S1_ssh-bruteforce-rule5763-authentication-failed.png)

## Lessons

- Recommended mitigations: SSH key-only authentication, fail2ban or Wazuh active-response IP blocking, and rate limiting.
- Triage signal: seeing both rule 5763 (real account targeted) and rule 5712 (account enumeration) from the same source in the same window tells the analyst whether existing accounts were attacked or usernames were being guessed.
