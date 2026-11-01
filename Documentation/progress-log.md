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

**Screenshots:** `INF-01_architecture-diagram.png` only (see checklist).

**LinkedIn draft (post when Phase 2 is done):**
Started building a SOC home lab: Wazuh SIEM + Suricata IDS monitoring an Active Directory environment, attacked from a separate Parrot Security workstation. First challenge: only one NIC per machine, so I built a logical lab network with IP aliasing (10.10.10.0/24) and a bridged VMware network. Lesson learned: adding a secondary IP on a DHCP adapter silently disables DHCP on Windows. Next: deploying the VMs and Active Directory. #SOC #BlueTeam #Wazuh #CyberSecurity #HomeLab

---

## 2026-11-01 - Phase 2: VM deployment (SOC-Server and DC01)

**Goal:** deploy the first VMs on VMnet0 and verify lab connectivity with PC1 and Parrot.

**Architecture change:** the Domain Controller uses Windows Server 2019 instead of 2022, because the 2019 ISO was available, it is lighter, and it is widely used in AD attack and detection labs.

**Done:**
- SOC-Server: Ubuntu Server 24.04.3 LTS, 4 vCPU, 8 GB RAM, 80 GB disk. `ens33` = VMnet0, static 10.10.10.20/24; `ens34` = NAT (DHCP) for updates.
- SOC-Server: root LV extended from 39 GB to 78 GB.
- SOC-Server: SSH works from Parrot and PC1. Fully updated. Snapshot `01-clean-install-network-ok` taken.
- DC01: Windows Server 2019 Standard Evaluation (Desktop Experience), 2 vCPU, 5 GB RAM, 60 GB disk. LAB adapter (VMnet0) static 10.10.10.10/24, no gateway; NAT adapter for updates.
- DC01: pings to 10.10.10.1, 10.10.10.20 and 10.10.10.50 succeed.
- Phase 1 open item closed: the VMnet0 bridge works with real VMs.

**Problems and fixes (lessons learned):**
1. ICMP redirects, duplicate ping replies (TTL 64 and 63) and 50% packet loss between the VM and Parrot. Cause: IP forwarding was enabled on PC1's `Ethernet` interface. Fix: `Set-NetIPInterface -InterfaceAlias "Ethernet" -AddressFamily IPv4 -Forwarding Disabled`, then `sudo ip route flush cache` on the Linux machines. After the fix: no redirects, no duplicates, 0% loss, TTL 64.
2. The Ubuntu installer uses only about half of the disk for the root LV by default. Fix: `sudo lvextend -r -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv`.
3. A VM network adapter set to "Bridged (Automatic)" can bind to the wrong host adapter. Fix: use Custom: VMnet0.
4. Easy Install in the VMware wizard preselected "Datacenter Core" (no GUI). Fix: pick the Desktop Experience edition.
5. TTL 128 appeared once on a ping from DC01 to the SOC-Server. Later checks showed ttl=64, a correct ARP table and forwarding disabled, so it was treated as a one-off.

**Open items:**
- DC01 snapshot.
- AD DS installation on DC01.
- Remaining VMs: Windows Client (10.10.10.30) and Ubuntu Server (10.10.10.40).
- Wazuh and Suricata are not installed on the SOC-Server yet.

---