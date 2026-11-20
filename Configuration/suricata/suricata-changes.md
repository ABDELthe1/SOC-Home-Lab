# Suricata configuration changes (SOC-Server)

Suricata 8.0.8 (OISF PPA). Changes made in `/etc/suricata/suricata.yaml`.

## HOME_NET

Only the four victim hosts. The Parrot attacker (10.10.10.50) is outside `HOME_NET`, so it counts as `EXTERNAL_NET`.

```yaml
HOME_NET: "[10.10.10.10,10.10.10.20,10.10.10.30,10.10.10.40]"
```

## Capture interface

`ens38` is a dedicated vNIC on VMnet0 with no IP, in promiscuous mode, with offloads disabled (see [capture-nic.service](capture-nic.service)). The BPF filter keeps only lab traffic, because the bridged segment also carries the host's internet traffic.

```yaml
af-packet:
  - interface: ens38
    bpf-filter: "net 10.10.10.0/24"
```

## EVE output

```yaml
community-id: true
```

## Rule sources

- Emerging Threats Open via `suricata-update`, merged into `/var/lib/suricata/rules/suricata.rules` (69,559 loaded, 53,582 enabled).
- Suricata built-in rules from `/usr/share/suricata/rules` (decoder, app-layer and stream events).
- No custom rules yet (Phase 8).

`eve.json` is forwarded to Wazuh by a localfile on the manager (see [../wazuh/agent-localfile-snippets.md](../wazuh/agent-localfile-snippets.md)). Wazuh matches all Suricata events with built-in rule 86601.
