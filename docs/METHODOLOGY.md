# Experimental methodology

## Claims under test

The repository makes three deliberately separate claims:

1. **Functional regression:** the configured deterministic rules detect each
   expected scenario in the synthetic attack corpus.
2. **Benign regression:** those same rules emit no alert for the curated benign
   corpus.
3. **Matching reference:** one previous replay session observed a 52 ns p50 and
   62 ns p95 from in-process event observation to matching-alert construction.

Only the first two are intended to reproduce exactly. The third is historical
context and is not a live, portable, or statistically characterized benchmark.

## Evaluation artifacts

| Artifact | Role |
|---|---|
| lab/events/attack-suite.jsonl | 22 normalized events representing 20 scenarios |
| lab/events/benign-suite.jsonl | 12 normalized negative-regression events |
| lab/ground-truth.yaml | Scenario-to-technique and expected-rule mapping |
| rules/runtime.yaml | 18 single-event rules |
| rules/sequences.yaml | 2 ordered temporal rules |
| cmd/benchmark | Evaluation CLI and acceptance gates |
| internal/benchmark | Corpus loading, matching, metrics, and report writers |
| benchmarks/reference | Reviewed historical result snapshot |

All fixtures use schema version 1.0. Attack events include scenario_id only for
evaluation joins; repository rules do not predicate on scenario_id.

## Corpus composition

### Attack corpus

The corpus contains 22 events because reverse-shell and download-execute each
require two ordered events. The remaining 18 scenarios use one event each.

| Event kind | Events |
|---|---:|
| process.exec | 11 |
| file.open | 7 |
| network.connect | 3 |
| privilege.setuid | 1 |
| **Total** | **22** |

The 20 scenarios map to 16 distinct ATT&CK technique identifiers. Repeated
technique IDs are retained because the scenarios exercise different observable
primitives and rules. The benchmark denominator is scenarios, not unique
techniques, despite the legacy report field being named techniques.

### Benign corpus

| Event kind | Events |
|---|---:|
| process.exec | 4 |
| file.open | 6 |
| network.connect | 2 |
| privilege.setuid | 0 |
| **Total** | **12** |

Negative cases include a normal interactive shell, internal service traffic,
reading /etc/passwd, writing an ordinary temporary log, normal web/container
processes, read-only cron/authorized_keys/systemd access, a failed Kubernetes
token read, internal DNS, and a standalone downloader.

This corpus is purpose-built for regression. It is too small and too curated to
estimate a production false-positive rate, workload specificity, or alert
volume.

## Benchmark procedure

The benchmark command performs the following steps:

1. Load and strictly validate every enabled YAML rule.
2. Load ground truth and reject missing, duplicate, or incomplete scenarios.
3. Decode attack and benign JSONL events and require timestamps.
4. Create a fresh detection engine for the attack corpus.
5. Disable behavioral scoring to isolate deterministic YAML rules.
6. Set observed_at immediately before processing each event.
7. Process attack events in file order and retain all alerts.
8. Repeat with a second fresh engine for benign events.
9. Join attack alerts to ground truth by scenario ID and expected rule ID.
10. Emit JSON, CSV, and Markdown reports.
11. Fail if recall is below 1.0 or benign alerts exceed zero, unless the caller
    explicitly changes those thresholds.

Reproduction:

    make benchmark

Equivalent direct invocation after build:

    ./bin/sentinel-benchmark \
      -events lab/events/attack-suite.jsonl \
      -benign lab/events/benign-suite.jsonl \
      -truth lab/ground-truth.yaml \
      -rules rules \
      -out reports \
      -fail-under 1 \
      -max-false-positives 0

Generated reports are intentionally ignored. The reviewed reference files are
kept separately so an ordinary benchmark does not silently rewrite historical
evidence.

## Metric definitions

### Scenario recall

For scenario s, detection is true when at least one attack alert:

- contains s in the scenario IDs derived from its evidence; and
- has a rule ID included in the scenario's expected_rules list.

    scenario recall = detected ground-truth scenarios / all ground-truth scenarios

Reference result:

    20 / 20 = 1.00 = 100%

This metric does not give credit solely for an unrelated alert on the same
event. It also does not penalize extra alerts on attack fixtures. The benchmark
does not report event-level precision or F1 because it has no independently
labeled classification unit for every possible alert.

### Benign alert count

Every deterministic alert emitted for the benign corpus counts as a false
positive:

    benign alerts = len(all benign-corpus alerts)

    false positives per 1,000 = benign alerts × 1,000 / benign events

Reference result:

    benign alerts = 0
    false positives per 1,000 fixture events = 0

The per-1,000 normalization is arithmetic over 12 fixtures, not an uncertainty
estimate and not an operational rate.

### Decision latency

For each alert:

    decision latency = alert construction time - latest observed_at in evidence

The engine clamps negative values to zero. For a detected scenario with more
than one eligible alert, the report retains the eligible alert with the lowest
latency.

The latency sample is sorted and percentile q uses:

    index = floor((sample_count - 1) × q)

There is no interpolation. With 20 scenario values, p50 selects index 9 and p95
selects index 18 in zero-based sorted order.

Because the benchmark overwrites observed_at immediately before Engine.Process,
this latency measures a narrow in-process path. It includes rule iteration up
to alert construction, but excludes:

- attack occurrence and syscall execution;
- eBPF program execution;
- ring-buffer reservation, transport, and user-space read;
- procfs enrichment;
- JSONL corpus loading;
- storage, alert serialization, API/SSE delivery, and dashboard rendering.

It must be called **matching replay latency**, not detection latency for a live
host.

## Reference session

The versioned snapshot records a previous engineering session generated at
2026-07-12T19:55:33.696596216Z:

| Result | Value |
|---|---:|
| Rules loaded | 20 |
| Scenarios | 20 |
| Detected | 20 |
| Scenario recall | 100% |
| Attack events | 22 |
| Benign events | 12 |
| Benign alerts | 0 |
| Matching latency p50 | 52 ns |
| Matching latency p95 | 62 ns |

The session's CPU model, host load, kernel, exact Go patch version, power state,
and run count were not captured. It appears to be a single report rather than a
repeated experiment. Individual values are retained for traceability in
[MATRIX.md](../benchmarks/reference/MATRIX.md) and
[matrix.csv](../benchmarks/reference/matrix.csv), but they cannot support
cross-machine comparison or a claim of stable nanosecond performance.

The report also recorded a 1,723,111 ns overall evaluation time. That timer
includes fixture parsing and processing but excludes rule loading, and was not
designed as a throughput measurement; it is therefore not promoted as a
headline result.

## Input integrity

SHA-256 digests for the artifacts evaluated by the reference snapshot:

| Artifact | SHA-256 |
|---|---|
| lab/events/attack-suite.jsonl | cb61764da8c9d8e55f1ea6461026de2955784f0b92ced490e8d8f31de76293d2 |
| lab/events/benign-suite.jsonl | 2230a22cf9b9fe9d8cb2d9be4e75edcd05160170e72e893375b49f423ad3aca6 |
| lab/ground-truth.yaml | f3d11ebaa724e5ffb6377ad234a0a15987e0e554fc200066a717678271591e67 |
| rules/runtime.yaml | 176771cde398a4cfec005519d04db03679911a7c68344152aaba7c59ccd42148 |
| rules/sequences.yaml | ed40127a69ad7c7501983613dc1188d549921f3555c35265c0b377cbd304c98f |

Verify from the repository root:

    sha256sum -c benchmarks/reference/inputs.sha256

These hashes bind the reference to inputs, not to a commit or signed
attestation. They detect accidental drift only when the manifest itself is
trusted.

## Reproducibility levels

| Property | Expected behavior |
|---|---|
| Rule count | Exact: 20 for the hashed inputs |
| Scenario result | Exact: every expected scenario detected |
| Benign alert count | Exact: zero for the hashed inputs |
| Rule selected per scenario | Exact unless rules/engine change |
| Event kinds used | Exact unless evidence selection changes |
| Individual latency | Non-deterministic |
| p50/p95 latency | Non-deterministic |
| Overall evaluation time | Non-deterministic |
| Live capture result | Not established by replay |

## Threats to validity

### Construct validity

The fixtures encode representative observables, not full adversary behavior.
For example, a marker named like a miner validates a predicate; it does not
model resource consumption, pool protocols, or miner evasion. ATT&CK mappings
describe intent, while the detector sees only a narrow syscall projection.

### Internal validity

Rules, ground truth, and fixtures are maintained in one repository. That makes
regression review simple but creates confirmation bias. Scenario IDs are
trusted labels, and the benchmark does not independently verify that fixture
semantics match their ATT&CK descriptions.

### External validity

Twelve benign events do not represent package management, CI workers, database
hosts, developer workstations, Kubernetes control planes, or long-running
production noise. The zero-alert result must not be generalized beyond these
records.

### Live/replay parity

Replay events are already normalized and fully populated. Live events can lose
records, truncate paths or argument suffixes, omit arguments after the sixth,
preserve relative paths, omit addresses for unsupported families, or miss
procfs enrichment.
Successful exec events refresh comm at syscall exit, but their richer
process/parent context is still best effort. Consequently, 100% replay recall
is not evidence of 100% live recall.

Live probe counters expose successful kernel submissions and known failure
paths, but they are not a ground-truth denominator. Pending failure counters can
refer to the same missing event, and an emitted record can still be rejected in
user space. A live experiment must publish every counter separately rather than
reporting their sum as "events lost."

### Timing validity

Nanosecond-scale values are dominated by clock-call cost, rule order, runtime
scheduling, CPU state, and a single observation. No warmup, repetitions,
confidence interval, CPU affinity, or environment manifest was recorded.

## Stronger next experiment

A defensible live performance study should:

1. Record commit, input hashes, binary/image digest, CPU, memory, kernel, Go
   version, BPF configuration, runtime, and power governor.
2. Generate ground-truthed events through fixed safe actors, not pre-normalized
   fixtures.
3. Timestamp actor intent, BPF entry/exit, ring read, post-enrichment, match,
   store, and client receipt separately.
4. Run warmups and at least 30 measured repetitions per workload.
5. Sweep event rate and concurrency while exporting ring/pending-map loss.
6. Report distributions and confidence intervals, not only p50/p95.
7. Include realistic benign workloads and a held-out scenario set reviewed by
   someone other than the rule author.
8. Publish raw run data and the analysis script with immutable provenance.

Until that protocol exists, the versioned reference should be read as a compact
functional proof with a narrowly scoped historical timing observation.
