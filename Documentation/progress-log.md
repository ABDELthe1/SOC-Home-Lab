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

## 2026-11-20 - Phase 6: Suricata IDS

**Goal:** add network detection with Suricata on the SOC-Server and forward its alerts to Wazuh.

**Done:**
- Suricata 8.0.8 (OISF PPA) installed on SOC-Server.
- Third vNIC `ens38` on VMnet0 for capture: no IP, promiscuous, GRO/LRO/TSO/GSO off, made persistent with the systemd unit `capture-nic.service` ([Configuration/suricata/capture-nic.service](../Configuration/suricata/capture-nic.service)).
- Rules: Emerging Threats Open via `suricata-update` (69,559 loaded, 53,582 enabled, merged into `/var/lib/suricata/rules/suricata.rules`) plus the Suricata built-in rules from `/usr/share/suricata/rules` (decoder, app-layer and stream events). No custom rules yet (Phase 8).
- `HOME_NET` set to the four victim hosts only (10.10.10.10, .20, .30, .40), so the Parrot attacker 10.10.10.50 counts as `EXTERNAL_NET`.
- BPF filter `net 10.10.10.0/24` on the capture interface.
- `eve.json` forwarded to Wazuh via a manager localfile (`log_format json`). Wazuh matches all Suricata events with built-in rule 86601.
- Configuration changes: [Configuration/suricata/suricata-changes.md](../Configuration/suricata/suricata-changes.md).
- Validated: `nmap -sS -sV -O` from Parrot to UBUNTU-SRV produced ET SCAN Potential SSH Scan (SID 2001219) and ET SCAN NMAP OS Detection Probe (SID 2018489), plus SURICATA ICMPv4 unknown code (2200025) and TCP wscale over maximum (2200130). The alerts are visible in Suricata (`fast.log` / `eve.json`) and in Wazuh (rule 86601, groups `ids`/`suricata`, `in_iface` `ens38`).

**Problems and fixes (lessons learned):**
1. Suricata also captured the host's internet traffic through the bridged segment (privacy and noise). Fix: BPF filter `net 10.10.10.0/24`.
2. A Wazuh manager restart caused a load spike (load average ~27 on 4 vCPUs) and a dashboard API timeout for a few minutes.
3. Manager events (agent 000) are only visible in the global Threat Hunting view.
4. Generic SURICATA STREAM alerts are noisy; they will be tuned in Phase 8.

**Screenshots:** `TEL-03_suricata-alerts-in-wazuh.png`.

**Open items:** Phase 7 (attack simulations) next.

---

## 2026-11-23 to 2026-11-24 - Phase 7: Attack simulations (S1-S5)

**Goal:** run five authorized attack scenarios against the lab and record real detections, to find gaps before building custom rules.

**Done:**
- S1 - SSH brute force (Hydra, 32 attempts) against UBUNTU-SRV: detected and escalated out of the box (rules 5712/5763, level 10). No gap.
- S2 - Nmap SYN/service/OS scan against UBUNTU-SRV: reached Wazuh via Suricata (rule 86601), but only at level 3, no correlation.
- S3 - Simulated suspicious PowerShell on WIN-CLIENT (recon, base64-encoded command, failed download cradle): detected out of the box, rule 92057 at level 12. No gap.
- S4 - AD enumeration and password spray (NetExec, 20 attempts) against DC01: NTLM/SMB path detected and escalated out of the box (rules 60122/60204), but the Kerberos path (4768/4771) was only caught generically (rule 60104, level 5), no dedicated rule or spray correlation.
- S5 - Simulated Linux privilege escalation and persistence on UBUNTU-SRV (new user, sudo group, cron persistence, SUID backdoor, `history -c`): everything logged by auditd but flat at level 3 (rules 80792/80791), FIM blind to `/tmp` and `/etc/cron.d`, no rule for history tampering.

Each scenario documented in its own file under `Attack-Simulations/` with scope, timing, detections, MITRE ATT&CK mapping and evidence screenshots.

**Findings carried into Phase 8:** S2 scan severity/correlation, S4 Kerberos 4768/4771 coverage, S5 FIM scope + severity + SUID detection + history-tampering detection.

**Screenshots:** `S1_ssh-bruteforce-rule5712-nonexistent-user.png`, `S1_ssh-bruteforce-rule5763-authentication-failed.png`, `S3_powershell-encoded-command-rule92057.png`, `S4_ad-spray-rule60122-list-20hits.png`, `S4_ad-spray-rule60204-escalation-detail.png`, `S5_linux-privesc-audit-events-level3.png`, `S5_linux-fim-gap-no-syscheck-results.png`, `TEL-03_suricata-alerts-in-wazuh.png`.

**Open items:** Phase 8 (detection engineering) next.

---

## 2026-11-24 to 2026-11-26 - Phase 8: Detection engineering (rules 100002-100010)

**Goal:** close the Phase 7 gaps with custom Wazuh local rules and expanded FIM scope.

**Done:** nine custom rules added on SOC-Server (`/var/ossec/etc/rules/local_rules.xml`), full detail and raw alert evidence in [Documentation/phase8-detection-engineering.md](phase8-detection-engineering.md):
- 100002 (level 12) - sudoers/cron FIM hit. Validated: 2x live alerts.
- 100003 (level 10) - `/etc/passwd`/`/etc/shadow` FIM hit. Deployed, no recorded validation alert.
- 100004 (level 7) - `/tmp` write FIM hit. Deployed, no recorded validation alert.
- 100005 (level 8) - Kerberos 4771 pre-auth failure. Validated: 5x live alerts (kerbrute spray).
- 100006 (level 8) - Kerberos 4768 TGT request. Deployed, not triggered by the kerbrute test; no recorded validation alert.
- 100007 (level 12) - Kerberos spray frequency correlation. Validated: 1x live alert.
- 100008 (level 10) - `usermod`/`gpasswd` privilege-group modification (auditd). Validated: 1x live alert.
- 100009 (level 12) - SUID bit set via FIM (`chmod u+s`). Validated: fired on `u+s`, correctly silent on `u-s`. Limitation: only matches the `rws` pattern, misses SUID-without-exec (`rwS`).
- 100010 (level 12) - `.bash_history` modified or deleted via FIM. Validated on both modify (550) and delete (553). Limitation: fires on any change, does not catch in-memory `history -c`.

**Problems and fixes (lessons learned):**
1. Rule 100009's first version used `<field name="syscheck.path">`/`<field name="syscheck.perm_after">`, by false analogy with working `win.*` fields. It never fired. Root cause, found by inspecting Wazuh's own shipped ruleset (`/var/ossec/ruleset/rules/0015-ossec_rules.xml`): syscheck events are injected into `analysisd` directly by the FIM module and decoded via `<category>`/`<decoded_as>`, not `<field>` on path/perm. `wazuh-logtest` could not help debug this either, since it never sees syscheck events (confirmed: "No decoder matched" on every attempted line). Fix: rewrote 100009 to hook off `<if_sid>550</if_sid>` with a plain `<match>to 'rws</match>` substring, the same mechanism already used by rules 100002-100004.
2. A pre-existing `ossec.conf` on UBUNTU-SRV had a duplicate `<directories>` element inside `<rootcheck>` (left over from an earlier bulk edit), causing `syscheckd` config warnings. Fixed by removing the stray line; confirmed by a clean restart with zero `(1230)/(1202)/(1207)` warnings.
3. Recurring "Too many fields for JSON decoder" `wazuh-analysisd` errors, confirmed to correlate precisely with every `wazuh-manager` restart (inventory-harvester/syscollector sync burst). Non-fatal, does not block rule loading. Treated as a known platform limitation; not yet written up as its own section.
4. `$(agent.name)` and `$(syscheck.path)` fail to interpolate in rule descriptions on rules 100008-100010 (render blank); cosmetic only, the raw alert JSON carries the correct data.

**Open items:** rules 100003, 100004 and 100006 have no recorded validation alert in the repo. Whether to keep or remove the earlier, less reliable `audit-wazuh-suid` auditd-based SUID rules (now superseded by 100009) was never decided.

---

## 2026-11-24 to 2026-11-26 - Phase 9: Incident response reports (S6, S7)

**Goal:** write two incident response reports, NIST SP 800-61 format, treating S4 and S5 as real incidents.

**Done:**
- S6 - AD reconnaissance and password spray against DC01 (treats S4 as the incident): preparation/detection-analysis/containment/eradication-recovery/lessons-learned, built from the real S4 alert data (rules 60122/60204).
- S7 - Linux privilege escalation and persistence on UBUNTU-SRV (treats S5 as the incident): same NIST structure, includes an explicit per-step table mapping each S5 action to its detection gap at the time and the Phase 8 rule that now covers it, and an honest note that the Phase 8 rules were validated separately, not in one live re-run of the S5 chain.

**Problems and fixes (lessons learned):**
1. S6's rule 60122 count was initially stated as 20 (the total spray attempts); corrected to 18 (the actual alert count: 18x rule 60122 + 2x rule 60204 = 20 attempts), backed by dedicated count screenshots.
2. The S4/S6 narrative initially implied rule 100006 (Kerberos 4768) was validated alongside 100005/100007; corrected across S4, S6 and the technical report to state it was deployed but not triggered by the kerbrute test.
3. An early S7 draft assumed an attack order and that S5 modified `/etc/sudoers` directly; corrected to the real order and to `usermod -aG sudo` (group membership, not a direct sudoers edit), and corrected to state plainly that rule 100010 does not cover S5's actual anti-forensics step (`history -c`, in-memory, no file trace).

**Screenshots:** `S6-01_incident-timeline.png`, `S6-01b_rule60122-count-18.png`, `S6-01c_rule60204-count-2.png`, plus the S4/S5 evidence screenshots reused by reference.

**Open items:** Phase 10 (final documentation and publishing) next.

---

## 2026-11-26 - Phase 10: Final documentation and publishing

**Goal:** repo cleanup, README overhaul, technical report final pass, GitHub Pages publication.

**Done:**
- Repo cleanup: restored `S5_linux-fim-gap-no-syscheck-results.png` (deleted on disk but still referenced); promoted 6 of 19 untracked screenshots out of two `extra/` folders with renames and new doc references (`P8-03a/b/c` usermod pre-fix evidence, `S6-01b/c` count-correction evidence, `P8-01a` auditd pre-tuning evidence); 13 remaining untracked files left as-is.
- `technical-report.tex` rewrite: added full S6 coverage (previously missing entirely), extended Phase 7 from S4-only to all of S1-S5, added Phase 8 (detection engineering) and Phase 9 (incident response) sections, corrected the overstated claim that rule 100006 was validated, rebuilt the PDF (14 pages, no errors). Follow-up commit fixed two remaining stale claims: a UFW line (UFW was never installed) and a "planned scenarios" table still listing unused tools (Impacket, BloodHound).
- `README.md` full rewrite: 12-section structure (summary/status, objectives, architecture, project status, S1-S7 tables, detection engineering, technical report, screenshots, open items, repository structure, conventions/scope, tools). Removed several fabricated/stale claims (UFW, Impacket, BloodHound, Metasploit, Wireshark, fabricated planned files); added kerbrute and PowerShell to the tools list; kept the VM inventory table's vCPU/RAM/disk columns (virtual allocations, not physical host specs, so outside the no-hardware-specs rule).
- GitHub Pages enabled on the `main` branch root (Jekyll auto-renders `README.md`). The repo is public, so the published site is public; confirmed live and rendering correctly at `https://abdelthe1.github.io/SOC-Home-Lab/`.

**Problems and fixes (lessons learned):**
1. The technical report was far more stale than expected: asked only to add S7 coverage, discovered it had no S6 coverage at all and Phase 7 only covered S4. Required a full Phase 7-9 rewrite from real repo records rather than an incremental edit.
2. `Documentation/progress-log.md` itself was found to be stale at this point (last entry: Phase 6) - this is the gap these four entries close.

**Open items (documented honestly, not resolved):**
- Suricata STREAM alert tuning and S2's scan severity/correlation rules (S2 gap, not picked up in Phase 8, which focused on S4/S5).
- `history -c` / `HISTFILE` in-memory tampering remains undetected (no filesystem or syscall trace available to FIM or the current auditd rules).
- Rules 100003, 100004, 100006: deployed, no recorded validation alert.
- "Too many fields for JSON decoder" platform-limitation finding (Phase 8) not yet written up as its own section.
- Disposition of the older `audit-wazuh-suid` auditd rules (superseded by FIM rule 100009) not decided.
- 13 screenshots left untracked in `Screenshots/attack-evidence/extra/` and `Screenshots/wazuh-dashboard/extra/`.
