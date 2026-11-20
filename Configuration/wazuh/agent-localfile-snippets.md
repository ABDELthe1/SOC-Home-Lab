# Wazuh agent configuration snippets

Blocks added inside `<ossec_config>` in the agent's `ossec.conf`.

## Sysmon (WIN-CLIENT, DC01)

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## auditd (UBUNTU-SRV)

Rules: [../auditd/soc.rules](../auditd/soc.rules)

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

## File integrity monitoring (UBUNTU-SRV)

Inside the `<syscheck>` section:

```xml
<directories realtime="yes">/home/socadmin/fim-test</directories>
```

## Suricata eve.json (Wazuh manager on SOC-Server)

In the manager's `ossec.conf`, not an agent. Events appear as agent 000 and match built-in rule 86601.

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
