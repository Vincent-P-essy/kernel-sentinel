# Contributing

Every new detection needs a stable rule ID, MITRE mapping, positive fixture, negative fixture and
documented data dependency. Kernel probes must keep bounded loops, bounded copies and verifier-safe
memory access.

Run `make lint test benchmark` before submitting a change. Do not add exploit code, destructive lab
steps, production telemetry or host-specific binary objects that cannot be regenerated from source.
