# Vendored eBPF headers

`common.h`, `bpf_helpers.h`, and `bpf_helper_defs.h` are vendored from the Cilium eBPF Go
library examples at tag `v0.22.0` so the probe can be compiled reproducibly without relying on
distribution-specific libbpf headers.

Source: <https://github.com/cilium/ebpf/tree/v0.22.0/examples/headers>

The upstream project is BSD-2-Clause licensed. `bpf_helpers.h` additionally declares
`LGPL-2.1 OR BSD-2-Clause`; this repository uses it under BSD-2-Clause.
