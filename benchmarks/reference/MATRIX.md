# Detection matrix — previous reference session

**Functional result:** 20 of 20 synthetic scenarios detected; 0 alerts on 12
curated benign events.

**Timing boundary:** the individual values, p50 52 ns, and p95 62 ns are from
the previous replay session and measure only in-process matching after event
observation. They are not kernel-to-alert latency and are not expected to
reproduce exactly.

| Scenario ID | MITRE technique | Scenario | Detected | Matching replay latency | Events used | Rule |
|---|---|---|---:|---:|---|---|
| reverse-shell | T1059.004 | Unix shell reverse channel | Yes | 71 ns | network.connect + process.exec | KS-REVERSE-SHELL-001 |
| shadow-read | T1003.008 | Linux credential file access | Yes | 46 ns | file.open | KS-SHADOW-READ-001 |
| download-execute | T1105 | Transfer followed by execution | Yes | 47 ns | network.connect + process.exec | KS-DOWNLOAD-EXEC-001 |
| authorized-keys | T1098.004 | SSH authorized key persistence | Yes | 57 ns | file.open | KS-AUTHORIZED-KEYS-001 |
| web-shell | T1505.003 | Web server spawned shell | Yes | 61 ns | process.exec | KS-WEB-SHELL-001 |
| container-miner | T1496 | Container resource hijacking | Yes | 57 ns | process.exec | KS-CONTAINER-MINER-001 |
| escape-simulation | T1611 | Container escape simulation marker | Yes | 50 ns | process.exec | KS-ESCAPE-PROBE-001 |
| log-deletion | T1070.002 | Linux log deletion | Yes | 62 ns | process.exec | KS-LOG-DELETION-001 |
| cron-persistence | T1053.003 | Cron persistence | Yes | 53 ns | file.open | KS-CRON-PERSISTENCE-001 |
| systemd-persistence | T1543.002 | Systemd service persistence | Yes | 53 ns | file.open | KS-SYSTEMD-PERSISTENCE-001 |
| ssh-key-read | T1552.004 | Private key collection | Yes | 57 ns | file.open | KS-SSH-PRIVATE-KEY-001 |
| docker-socket | T1611 | Container control socket access | Yes | 46 ns | file.open | KS-DOCKER-SOCKET-001 |
| k8s-token | T1528 | Kubernetes token theft | Yes | 47 ns | file.open | KS-K8S-TOKEN-001 |
| namespace-entry | T1611 | Namespace entry primitive | Yes | 48 ns | process.exec | KS-NAMESPACE-TOOL-001 |
| setuid-root | T1548.001 | Setuid privilege transition | Yes | 51 ns | privilege.setuid | KS-SETUID-ROOT-001 |
| setuid-bit | T1548.001 | Setuid permission creation | Yes | 52 ns | process.exec | KS-SETUID-BINARY-001 |
| k8s-secrets | T1613 | Kubernetes secrets discovery | Yes | 53 ns | process.exec | KS-KUBECTL-SECRETS-001 |
| dns-exfil | T1048.003 | DNS exfiltration channel | Yes | 52 ns | network.connect | KS-DNS-EXFIL-001 |
| curl-pipe-shell | T1204.002 | Download piped to shell | Yes | 47 ns | process.exec | KS-CURL-PIPE-SHELL-001 |
| temp-execution | T1059 | Execution from shared memory | Yes | 52 ns | process.exec | KS-EXEC-TEMP-001 |

## Interpretation

- Detected means an alert carried the scenario ID in its evidence and used a
  rule listed as expected by ground truth.
- Events used lists distinct normalized event kinds, not the number of events.
- Several rows share a MITRE identifier; the denominator is 20 scenarios, not
  20 unique techniques.
- Extra alerts on attack fixtures are outside the current metric. Every alert
  on the benign fixture counts as a false positive.
- See [the full methodology](../../docs/METHODOLOGY.md) before comparing these
  numbers with another system.
