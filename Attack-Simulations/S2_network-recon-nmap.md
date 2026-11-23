# S2 - Network reconnaissance (Nmap)

## Scenario

Network reconnaissance from the Parrot attacker (10.10.10.50) against UBUNTU-SRV (10.10.10.40).

```
nmap -sS -sV -O -T4 -p 1-1000 10.10.10.40
```

## Objective

Check that a SYN scan with service and OS detection is detected by Suricata and reaches Wazuh.

## Scope

Lab network 10.10.10.0/24 only. Source: Parrot (10.10.10.50). Target: UBUNTU-SRV (10.10.10.40).

## Time

2026-11-20, scans at about 21:08 and 21:15.

## Expected detections

Suricata scan alerts on the capture interface, forwarded to Wazuh (detection source for this scenario in the README).

## Detections observed

| SID | Signature | Source |
|---|---|---|
| 2001219 | ET SCAN Potential SSH Scan | Suricata (ET Open) |
| 2018489 | ET SCAN NMAP OS Detection Probe | Suricata (ET Open) |
| 2200025 | SURICATA ICMPv4 unknown code | Suricata (built-in) |
| 2200130 | SURICATA TCP wscale over maximum | Suricata (built-in) |

All four reached Wazuh as rule 86601, level 3, groups `ids` / `suricata`, `in_iface` `ens38`.

## Missed or weak detections

Gaps (to fix in Phase 8):
- All scan alerts are only level 3.
- No host-side detection on UBUNTU-SRV.
- No aggregated "many ports probed" correlation.

Planned fixes:
- Custom Wazuh rule raising the severity of ET SCAN alerts.
- Correlation rule for repeated scan alerts from one source.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1046 | Network Service Discovery |
| T1595 | Active Scanning |

## Evidence

- [Screenshots/wazuh-dashboard/TEL-03_suricata-alerts-in-wazuh.png](../Screenshots/wazuh-dashboard/TEL-03_suricata-alerts-in-wazuh.png)

## Lessons

- Suricata with ET Open and its built-in rules detects an Nmap SYN, version and OS scan, and every alert reaches Wazuh.
- Detection works, but the alerts are not prioritised: at level 3 with no correlation, a scan is easy to miss among other events. Severity and correlation rules are needed in Phase 8.
