# Versioned benchmark reference

This directory freezes the reviewed result of the previous Kernel Sentinel
engineering session. It is separate from reports/, which is generated locally
and ignored by Git.

## Reference result

| Field | Value |
|---|---:|
| Generated at | 2026-07-12T19:55:33.696596216Z |
| Rules | 20 |
| Attack scenarios | 20 |
| Attack events | 22 |
| Detected scenarios | 20 |
| Scenario recall | **100%** |
| Benign events | 12 |
| Benign alerts | **0** |
| False positives per 1,000 fixture events | 0 |
| Matching replay latency p50 | **52 ns** |
| Matching replay latency p95 | **62 ns** |

The functional result is scoped to the hashed synthetic corpora. Zero alerts
on 12 curated benign records is not a production false-positive estimate.

The p50/p95 values are retained from the previous session and cover only
in-process matching replay: observed_at was reset immediately before the
detection engine processed each event. They exclude kernel capture, eBPF work,
ring-buffer transport, enrichment, parsing, storage, serialization, API/SSE
delivery, and rendering. Environment metadata and repeated samples were not
captured, so these values are not a portable performance claim.

## Files

| File | Purpose |
|---|---|
| [MATRIX.md](MATRIX.md) | Human-readable scenario evidence |
| [matrix.csv](matrix.csv) | Machine-readable scenario evidence |
| [inputs.sha256](inputs.sha256) | Hashes binding this snapshot to rules and fixtures |

## Verify inputs

From the repository root:

    sha256sum -c benchmarks/reference/inputs.sha256

Expected functional reproduction:

    make benchmark

The new reports should retain 20/20 scenario recall and zero alerts on the
12-event benign fixture. Individual nanosecond values are expected to differ.

## Update protocol

A future reference update should be reviewable as evidence, not a cosmetic
refresh:

1. Run formatting, vetting, tests, race tests, build, and benchmark.
2. Record commit, CPU, kernel, Go version, image digest, and command line.
3. Preserve raw JSON output and multiple run samples when timing is reported.
4. Recompute inputs.sha256.
5. Explain every functional or latency delta in the change description.
6. Keep historical references or tag the superseded version.

Reference prepared for the project authored by **Vincent Plessy**.
