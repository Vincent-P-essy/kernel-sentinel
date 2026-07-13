# Security policy

Report vulnerabilities through GitHub Security Advisories. Do not attach production telemetry,
host identifiers, credentials, or container secrets to a public issue.

Replay mode is the default and needs no elevated privileges. Live mode loads eBPF programs and
must be deployed only by an authorized host administrator after reviewing the probe and rules.
The project never blocks a syscall; it is an observe-and-alert engine.
