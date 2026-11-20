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
## 2026-11-13 - Phase 3: Active Directory

**Goal:** promote DC01 to a Domain Controller and build the domain structure.

**Done:**
- DC01 (Windows Server 2019 Standard Evaluation, Desktop Experience) runs AD DS and DNS for the domain `SOC-LAB.LOCAL`, with DNS forwarder 8.8.8.8.
- OU structure: `SOC-LAB` containing Users, Administrators, IT Department, HR Department, Finance Department, Computers, Servers.
- Users created and enabled: `IT_User` (IT Department), `HR_User` (HR Department), `Finance_User` (Finance Department), `Standard_User` (Users). Built-in Administrator exists.

**Problems and fixes (lessons learned):**
1. DC01 registered its NAT adapter address in DNS, so `soc-lab.local` resolved to two IPs. Fix: `Set-DnsClient -InterfaceAlias NAT -RegisterThisConnectionsAddress $false`, `dnscmd /ResetListenAddresses 10.10.10.10`, delete the stale A records in `SOC-LAB.LOCAL` and `_msdcs.SOC-LAB.LOCAL`, restart DNS and Netlogon, then `nltest /dsregdns`. The same setting was applied on WIN-CLIENT before the domain join. Lesson: multi-homed lab machines must not register the temporary NAT adapter in AD DNS.

**Screenshots:** `INF-04_domain-users-and-ous.png`.

---

## 2026-11-16 - Phase 2 complete: WIN-CLIENT and UBUNTU-SRV

**Goal:** deploy the remaining two VMs, join the client to the domain and verify lab connectivity.

**Done:**
- WIN-CLIENT: Windows 10 Pro, 2 vCPU, 5 GB RAM, 60 GB disk. LAB adapter (VMnet0) static 10.10.10.30/24, no gateway, DNS 10.10.10.10; second adapter on NAT, not registered in DNS.
- WIN-CLIENT: joined to `SOC-LAB.LOCAL`; computer object in `OU=Computers,OU=SOC-LAB,DC=SOC-LAB,DC=LOCAL`. Login as `SOC-LAB\IT_User` verified (`whoami` and domain name checked).
- UBUNTU-SRV: Ubuntu Server 24.04.3 LTS, 2 vCPU, 2 GB RAM, 30 GB disk; root LV extended to 28 GB. `ens33` = VMnet0, static 10.10.10.40/24 (no gateway); `ens34` = NAT (DHCP).
- UBUNTU-SRV: OpenSSH installed; SSH works from Parrot. Ping verified to 10.10.10.10, 10.10.10.20 and 10.10.10.50.
- All four VMs are created and reach each other on 10.10.10.0/24. Phase 2 is done.

**Problems and fixes (lessons learned):**
1. WIN-CLIENT was installed with only a NAT adapter. Fix: the lab adapter on VMnet0 was hot-added afterwards in VM Settings.
2. SSH to 10.10.10.40 during the Ubuntu install reached the installer's temporary SSH server (different host key and password), causing "Permission denied" and a changed host key warning after the reboot. Fix: `ssh-keygen -R` for the old entry. Lesson: do not SSH into a VM until the install is finished and rebooted.
3. On Linux, a password typed during the install used the US keyboard layout. Fix: if SSH rejects it, reset it from the VM console with `sudo passwd`.

**Open items (Phase 4 and later):**
- Wazuh and Suricata on the SOC-Server.
- Sysmon and Wazuh agent on WIN-CLIENT.
- auditd, UFW and Wazuh agent on UBUNTU-SRV.

---

## 2026-11-20 - Phase 4: Wazuh SIEM and agents

**Goal:** deploy the Wazuh SIEM and register agents on the lab endpoints.

**Done:**
- Wazuh 4.14.10 all-in-one installed on SOC-Server (10.10.10.20).
- Agents registered on DC01, WIN-CLIENT and UBUNTU-SRV.
- VMs moved from the USB disk to NVMe (`C:\VMs\project`) to fix 100% disk activity and slowness.

**Problems and fixes (lessons learned):**
1. The dashboard showed "No API available" / HTTP 429. Cause: retries during start-up. Fix: wait until the services are fully up and use one browser tab.

---

## 2026-11-20 - Phase 5: Endpoint monitoring (Sysmon, auditd, FIM)

**Goal:** collect endpoint telemetry from Windows and Linux and validate that Wazuh raises alerts.

**Done:**
- WIN-CLIENT and DC01: Sysmon (SwiftOnSecurity config), collected by the Wazuh agent via an `eventchannel` localfile.
- WIN-CLIENT and DC01: Windows audit policies set with `auditpol` (Logon, Account Lockout, Credential Validation, User/Group Management, Process Creation; Kerberos on DC01).
- Validated: a failed logon to DC01 from WIN-CLIENT produced Event 4625 and the rule "Logon Failure - Unknown user or bad password" (level 5).
- UBUNTU-SRV: auditd rules ([Configuration/auditd/soc.rules](../Configuration/auditd/soc.rules)) and FIM in realtime on `/home/socadmin/fim-test`.
- Validated: a file added in the FIM folder raised rule 554; `useradd` / `userdel` produced rules 80781, 80791 and 80792.
- Agent configuration snippets: [Configuration/wazuh/agent-localfile-snippets.md](../Configuration/wazuh/agent-localfile-snippets.md).

**Problems and fixes (lessons learned):**
1. The initial auditd rule logging every root `execve` produced about 1,600 events in 15 minutes. Fix: restricted to `auid>=1000` and switched the watch keys to `audit-wazuh-w` so the Wazuh built-in rules fire.
2. VM time zones differ (DC01 is on Pacific time). UTC timestamps were verified correct.

**Screenshots:** `TEL-01_sysmon-events-in-wazuh.png`.

**Open items:** Phase 6 (Suricata IDS) next.

---
