# Progress Log

Real configuration and results only. One entry per working session.

---

## 2026-11-01 - Phase 1: Network preparation

**Goal:** connect PC1 (Windows 11 host) and PC2 (Parrot) over a logical lab subnet, using a single NIC on each machine.

**Design:** IP aliasing. Lab subnet 10.10.10.0/24 with no gateway, added on top of the existing home LAN 192.168.1.0/24. VMs will attach through VMware VMnet0 bridged to the physical adapter.

**Done:**
- PC1: static 192.168.1.8/24 (gateway and DNS 192.168.1.1) plus alias 10.10.10.1/24 on `Ethernet`.
- PC1: firewall rule allowing inbound ICMPv4 from 10.10.10.0/24.
- PC2: live alias 10.10.10.50/24 on the wired interface, made persistent in the NetworkManager profile (applies at next reconnect).
- Cross-ping verified in both directions; Parrot kept its internet access.
- VMware: added VMnet0 in the Virtual Network Editor and confirmed VMware Bridge Protocol is enabled on the host's physical wired Ethernet adapter.

**Problems and fixes (lessons learned):**
1. Adding the alias with `New-NetIPAddress` on a DHCP-enabled adapter disabled DHCP and removed the 192.168.1.8 lease, so PC1 lost internet. Fix: set a static primary address with `netsh`, then add the alias. Windows cannot keep a DHCP primary and a static secondary address on one adapter.
2. `ipconfig` did not list the new alias immediately because Windows hides tentative addresses until duplicate-address detection finishes. `Get-NetIPAddress` showed the real state.
3. On Parrot, `nmcli con up` would have dropped the SSH session. The alias was added live with `ip addr add` first, and the profile was changed without reactivating it.

**Open item:** final bridge test with the first VM (SOC Server at 10.10.10.20).

**Screenshots:** P1-01 to P1-08 (see checklist).

**LinkedIn draft (post when Phase 2 is done):**
Started building a SOC home lab: Wazuh SIEM + Suricata IDS monitoring an Active Directory environment, attacked from a separate Parrot Security workstation. First challenge: only one NIC per machine, so I built a logical lab network with IP aliasing (10.10.10.0/24) and a bridged VMware network. Lesson learned: adding a secondary IP on a DHCP adapter silently disables DHCP on Windows. Next: deploying the VMs and Active Directory. #SOC #BlueTeam #Wazuh #CyberSecurity #HomeLab

---
