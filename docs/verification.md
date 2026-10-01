# Execution record

Source revision: `a78f64690640ba55daaf2a8a6434218a3efa7223`.

Attack-suite JSONL events replayed through the rule engine and displayed in the running dashboard. This capture uses replay mode, not live eBPF probes.

`go test ./...`: passed. `go build -o bin/kernel-sentinel ./cmd/sentinel`: passed. The dashboard was exercised with `-source replay -replay lab/events/attack-suite.jsonl`. Live kernel probe loading was not tested.

The image is a browser capture of the running local application.

This check covers the local example and the commands listed above. Deployment, external integrations and performance under production load are outside this record.
