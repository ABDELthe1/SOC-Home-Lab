# Screenshot Checklist (essentials only)

Naming: `<id>_<description>.png`, saved in `Screenshots/` (subfolders `wazuh-dashboard/`, `security-alerts/`, `attack-evidence/`).
Before saving: hide passwords, tokens, public IPs and MAC addresses.
Rule: one screenshot must prove one thing. Skip anything that only shows a step was typed.

## Infrastructure (4)

- [ ] `INF-01_architecture-diagram.png` - exported Excalidraw diagram [LinkedIn]
- [x] `INF-02_vmware-all-vms-running.png` - four VMs running in VMware
- [ ] `INF-03_wazuh-dashboard-agents-active.png` - three agents Active in the Wazuh dashboard [LinkedIn]
- [x] `INF-04_domain-users-and-ous.png` - Active Directory users and OUs (SOC-LAB.LOCAL)

## Telemetry (3)

- [ ] `TEL-01_sysmon-events-in-wazuh.png` - Sysmon events from the Windows client in Wazuh
- [ ] `TEL-02_windows-4625-events.png` - Event ID 4625 / 4624 in Wazuh
- [ ] `TEL-03_suricata-alerts-in-wazuh.png` - Suricata events integrated in Wazuh

## Attacks and detections (2 per scenario)

Per scenario: one screenshot of the attack, one of the Wazuh/Suricata alert (with source IP, target, timestamp).

- [ ] `S1-01_hydra-attack.png` / `S1-02_alert-ssh-bruteforce.png`
- [ ] `S2-01_nmap-scan.png` / `S2-02_alert-suricata-portscan.png`
- [ ] `S3-01_powershell-command.png` / `S3-02_alert-suspicious-powershell.png`
- [ ] `S4-01_netexec-impacket-enum.png` / `S4-02_alert-ad-enumeration.png`
- [ ] `S5-01_sudo-privilege-activity.png` / `S5-02_alert-auditd-sudo.png`
- [ ] `S6-01_incident-timeline.png` / `S6-02_containment-and-recovery.png`

## Detection engineering (2)

- [ ] `DET-01_custom-rule-fired.png` - custom Wazuh rule triggering an alert [LinkedIn]
- [ ] `DET-02_dashboard-overview.png` - final dashboard with alerts over time [LinkedIn]

Total: 25. Add more only when something is unusual or worth showing.