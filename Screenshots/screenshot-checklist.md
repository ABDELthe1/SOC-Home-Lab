# Screenshot Checklist

Naming: `P<phase>-<nn>_<description>.png`
Save in `Screenshots/` (subfolders from Phase 4: `wazuh-dashboard/`, `security-alerts/`, `attack-evidence/`).
Before saving: hide passwords, tokens, public IPs, MAC addresses and personal data.

Legend: [ ] to take, [x] taken. Mark `[LinkedIn]` items as the best candidates for posts.

## Phase 1 - Network preparation

- [ ] `P1-01_pc1-ipconfig-alias.png` - PC1 `ipconfig` showing 192.168.1.8 and 10.10.10.1 on Ethernet
- [ ] `P1-02_pc1-netipaddress-preferred.png` - `Get-NetIPAddress` output, both addresses Preferred
- [ ] `P1-03_parrot-ip-alias.png` - Parrot `ip -br a show eno1` showing 192.168.1.12 and 10.10.10.50
- [ ] `P1-04_ping-parrot-to-pc1.png` - Parrot pinging 10.10.10.1
- [ ] `P1-05_ping-pc1-to-parrot.png` - PC1 pinging 10.10.10.50
- [ ] `P1-06_vmware-vmnet0-bridged.png` - Virtual Network Editor with VMnet0 Bridged to the host's physical wired Ethernet adapter
- [ ] `P1-07_vmware-bridge-protocol.png` - Ethernet properties with VMware Bridge Protocol ticked
- [ ] `P1-08_architecture-diagram.png` - exported Excalidraw diagram [LinkedIn]

## Phase 2 - VM deployment (SOC Server first)

- [ ] `P2-01_soc-vm-settings.png` - VM hardware summary (4 CPU, 8 GB, 80 GB, network adapters)
- [ ] `P2-02_soc-ubuntu-network-config.png` - installer static IP screen (10.10.10.20)
- [ ] `P2-03_soc-ip-and-ping.png` - `ip -br a` plus pings to 10.10.10.1 and 10.10.10.50
- [ ] `P2-04_ping-from-parrot-to-soc.png` - Parrot pinging 10.10.10.20 (bridge test)
- [ ] `P2-05_vmware-library-all-vms.png` - all four VMs listed in VMware [LinkedIn]

Next phases are added as we reach them.
