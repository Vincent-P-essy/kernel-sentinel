package probe

//go:generate go tool bpf2go -tags linux bpf ../../bpf/sentinel.bpf.c -- -I../../bpf/headers
