# SOC Home Lab - Cyberattack Detection, Monitoring and Incident Response

Enterprise-inspired Security Operations Center (SOC) built at home: a Wazuh SIEM and Suricata IDS monitor a small Active Directory environment that is attacked in a controlled way from a separate Parrot Security workstation. The full cycle is practiced and documented: attack, collect, detect, alert, investigate, contain, remediate, report.

**Status:** Phase 1 (network preparation) complete, Phase 2 (VM deployment) in progress - see [Project Status](#6-project-status).

---

## 1. Objectives

1. Generate controlled cyberattacks against an isolated lab.
2. Collect endpoint and network telemetry centrally.
3. Detect suspicious activity with default and custom rules.
4. Investigate alerts: source, target, user, timeline, impact.
5. Contain and remediate (NIST incident response lifecycle).
6. Document every incident with evidence and a professional report.

## 2. Architecture

![Architecture](Architecture/soc-architecture.png)

> Export the Excalidraw diagram to `Architecture/soc-architecture.png`.

| Component | Role |
|---|---|
| PC1 (Windows 11 + VMware Workstation) | Hosts 4 VMs |
| PC2 (Parrot Security 7.4) | Red Team / attacker workstation (physical machine) |
| VM1 SOC Server | Wazuh Manager + Indexer + Dashboard, Suricata IDS |
| VM2 Windows Server 2019 | Domain Controller (AD DS, DNS), Sysmon, Wazuh agent |
| VM3 Windows 10/11 | Domain-joined employee workstation, Sysmon, Wazuh agent |
| VM4 Ubuntu Server 24.04 | Linux server, SSH, auditd, UFW, Wazuh agent |

## 3. Network design (single NIC, logical isolation)

Neither PC has a second NIC, so the lab subnet is created by **IP aliasing** on the existing interface. The lab is logically separated, not physically separated.

| Item | Value |
|---|---|
| Home LAN (unchanged) | 192.168.1.0/24, gateway 192.168.1.1 |
| Lab subnet | 10.10.10.0/24, **no default gateway** |
| VMware network | VMnet0 (bridged to the physical Ethernet adapter) |
| Internet for VMs | Temporary NAT adapter (VMnet8), removed after updates |

| Device | Home LAN | Lab IP |
|---|---|---|
| PC1 host | 192.168.1.8 (static) | 10.10.10.1 (alias) |
| PC2 Parrot | 192.168.1.12 (DHCP) | 10.10.10.50 (alias) |
| Windows Server 2019 (DC) | - | 10.10.10.10 |
| SOC Server | - | 10.10.10.20 |
| Windows Client | - | 10.10.10.30 |
| Ubuntu Server | - | 10.10.10.40 |

Isolation rules:
- Lab IPs have no gateway, so the router never routes 10.10.10.0/24.
- Attack tools are scoped to 10.10.10.0/24 only.
- No home device is placed in 10.10.10.0/24.
- Nothing in the lab is exposed to the internet.

Known limitation: the lab shares the physical wire with home devices. A direct cable between the PCs or a dedicated switch is a future improvement.

Suricata runs on a second vNIC of the SOC Server (promiscuous mode, no IP) attached to VMnet0, so it sees traffic that reaches PC1's NIC and traffic on the virtual switch. Visibility is validated before any detection is trusted.

## 4. VM inventory

| VM | OS | vCPU | RAM | Disk | Lab IP |
|---|---|---|---|---|---|
| SOC-Server | Ubuntu Server 24.04.3 LTS | 4 | 8 GB | 80 GB (root LV 78 GB) | 10.10.10.20 |
| DC01 | Windows Server 2019 Standard Evaluation (Desktop Experience) | 2 | 5 GB | 60 GB | 10.10.10.10 |
| WIN-CLIENT | Windows 10/11 | 2 | 5 GB | 60 GB | 10.10.10.30 |
| UBUNTU-SRV | Ubuntu Server 24.04 LTS | 2 | 2 GB | 30 GB | 10.10.10.40 |

Domain: `SOC-LAB.LOCAL`

Each VM has a lab adapter on VMnet0 (static lab IP, no gateway) and a temporary NAT adapter (VMnet8) for updates only.

Architecture change: the Domain Controller uses Windows Server 2019 instead of 2022, because the 2019 ISO was available, it is lighter, and it is widely used in AD attack and detection labs.

## 5. Attack scenarios (all inside the authorized lab)

| # | Scenario | Source -> Target | Tools | Detection |
|---|---|---|---|---|
| 1 | Brute force | Parrot -> Ubuntu / DC | Hydra | Auth logs + Wazuh rules |
| 2 | Port scanning | Parrot -> DC / Ubuntu | Nmap | Suricata |
| 3 | Suspicious PowerShell | Windows client | PowerShell | Sysmon + Wazuh |
| 4 | Active Directory attacks | Parrot -> DC | Impacket, NetExec, BloodHound | Windows Security + Sysmon + Wazuh |
| 5 | Linux privilege indicators | Parrot / local -> Ubuntu | CLI, SSH | auditd + Wazuh |
| 6 | Incident response | Alerts from 1-5 | Wazuh dashboard | Full investigation and report |

A detection counts as successful only when the event is generated, collected, analyzed and verified.

## 6. Project status

| Phase | Description | Status |
|---|---|---|
| 1 | Infrastructure and network preparation | Done |
| 2 | VM deployment | In progress (SOC-Server done, DC01 created and network verified, Windows Client and Ubuntu Server pending) |
| 3 | Active Directory | Next |
| 4 | Wazuh SIEM and agents | Pending |
| 5 | Endpoint monitoring (Sysmon, auditd, FIM) | Pending |
| 6 | Suricata IDS | Pending |
| 7 | Attack simulations | Pending |
| 8 | Detection engineering | Pending |
| 9 | Incident response | Pending |
| 10 | Final documentation | Pending |

Day-by-day record: [Documentation/progress-log.md](Documentation/progress-log.md)
Evidence checklist: [Screenshots/screenshot-checklist.md](Screenshots/screenshot-checklist.md)

## 7. Repository structure

```
SOC-Home-Lab/
|-- README.md
|-- Architecture/          diagrams, vm-inventory.md
|-- Installation/          setup guides per component
|-- Configuration/         sysmon, wazuh, suricata, auditd
|-- Attack-Simulations/    01-brute-force ... 06-incident-response
|-- Detection-Rules/       wazuh-custom-rules, suricata-rules
|-- Incident-Reports/      incident-001.md, incident-002.md, template
|-- Automation/            alert-analysis.py
|-- Screenshots/           wazuh-dashboard, security-alerts, attack-evidence
`-- Documentation/         progress-log.md, technical-report.md, lessons-learned.md
```

## 8. Conventions

- Screenshot names: `<id>_<description>.png`, for example `S1-02_alert-ssh-bruteforce.png`. Only essential evidence is kept (see the checklist).
- Record real configurations and real results only.
- Never commit passwords, keys, tokens, real logs or personal data. Blur or remove them before uploading.
- Snapshot every VM before major changes.

## 9. Scope and ethics

All attacks target only the authorized lab network 10.10.10.0/24, owned by the author. No lab system is exposed to the internet.

## 10. Tools

Wazuh, Suricata, Sysmon, auditd, Active Directory, VMware Workstation, Parrot Security, Nmap, Hydra, Impacket, NetExec, Metasploit, Wireshark.