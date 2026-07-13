module github.com/Vincent-P-essy/kernel-sentinel

go 1.25.0

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.43.0
	gopkg.in/yaml.v3 v3.0.1
)

tool github.com/cilium/ebpf/cmd/bpf2go
