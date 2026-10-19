# Hot-path benchmark results

This report covers the four latest optimizations on the
[`peer-policy-hotpaths-20261019` review branch](https://github.com/kradalby/headscale/tree/peer-policy-hotpaths-20261019).
Each keeps original code for differential checks and paired benchmarks.
See the [current and original code](hotpath-code.md) and
[results and costs for all 19 optimizations](hotpath-tradeoffs.md).

The measured source is commit
[`e38b62bcf`](https://github.com/kradalby/headscale/commit/e38b62bcf21c3abfe160656499fdf00079a340ec).
Go 1.27.2, linux/amd64, i9-13900K, one Go P, no CPU affinity;
medians of three serial 150 ms runs. Parsing, renderer and SSH benchmarks
use normal Info logging and restore the previous level. These are
function or workload measurements, not whole-server throughput or
statistical significance claims.

## Results suitable for a comment

| Workload                                 |  Original |   Current | Speedup |
| ---------------------------------------- | --------: | --------: | ------: |
| Render 1 peer; 10000 attributed nodes    | 373.92 us |   3.02 us | 123.81x |
| Render 8 peers; 10000 attributed nodes   | 383.42 us |  11.70 us |  32.78x |
| SSH: 256 nodes, 32 repeated-source rules |  21.52 ms |   6.18 ms |   3.48x |
| Unchanged DNS: 10000 JSON records        |   4.68 ms | 541.20 us |   8.65x |
| Unchanged DNS: 10000 HuJSON records      |  22.41 ms | 555.90 us |  40.32x |
| Unchanged DNS: 10000 YAML records        |  54.08 ms | 533.14 us | 101.43x |
| Test assertion: dense mesh, 512 clients  | 266.04 ms |  31.97 ms |   8.32x |

Controls and costs:

- Capability rendering: one-peer allocation falls **298097 → 2689 B/op**,
  56 → 24 allocations. Full 9999-peer rendering is **16.30 → 16.32 ms**.
  Sparse attributes use the existing bulk-copy path when it is smaller.
  The accessor takes one coherent policy lock and retains no new index;
  output flags and address shaping match the original.
- SSH: single-rule controls remain similar. Unique small sources are
  **103.1 → 110.6 us** (+7.2%, +3036 B/op); unique dense sources are about
  2% slower. Reuse is call-local; independent principal objects remain
  independent.
- DNS: files are still read and hashed. Changed JSON/HuJSON/YAML controls
  remain around **6.1/24/57 ms**. Event frequency is unmeasured. The
  optimization adds no persistent cache and does not cache rejected content.
- Test assertions: the 512-client dense case allocates **14.06 MB temporarily**
  (256 clients: 3.52 MB); indexes die with the call. Small meshes and short
  rows retain scans. Eight-client dense control: **2.12 → 2.18 us**, zero
  allocations. Sparse 512-client control: **7.21 → 7.58 ms** (+5%), zero
  allocations. Two-client long misses remain near 24 us. This gain applies
  to the test harness.

## Reproduction

Run serially from the repository root, with Go 1.27.2:

```sh
go test ./hscontrol/policy/v2 -run '^$' -bench '^(BenchmarkNodeCapMapsSelection|BenchmarkNodeCapMapsConstruction|BenchmarkCompileSSHPolicyReuse)$' -benchtime=150ms -count=3 -cpu=1
go test ./hscontrol/mapper -run '^$' -bench '^BenchmarkBuildTailPeersCapMaps$' -benchtime=150ms -count=3 -cpu=1
go test ./hscontrol/dns -run '^$' -bench '^BenchmarkExtraRecordsUpdate$' -benchtime=150ms -count=3 -cpu=1
go test ./hscontrol/servertest -run '^$' -bench '^(BenchmarkAssertSymmetricVisibility|BenchmarkAssertSymmetricVisibilityPositions)$' -benchtime=150ms -count=3 -cpu=1
```

The selection microbenchmark isolates the accessor. The renderer results
above measure the complete renderer; the two should not be substituted
for each other.

## Validation

The following checks passed for the measured source:

- Full CI-profile suite across 29 tested packages:
  `CI=true go test ./... -count=1 -timeout=20m -p=2 -parallel=4`.
- Complete race suites for `hscontrol/policy/v2`, `hscontrol/mapper`,
  `hscontrol/state` and `hscontrol/dns`, plus focused assertion races
  covering the final scan, index, publication-generation and panic fixtures.
- Final integrated lint: zero issues. Mandatory commit hooks passed for
  all 20 source commits.
- All 13 additional reference function bodies match the pre-change commit
  `d00f135bf` after naming, import-alias and formatting normalization.
- Serial benchmark runs completed cleanly, with three samples per case.
  Separate heap probes were not used to claim exact retained memory for
  the assertion index.

Review found and fixed same-pointer publication invalidation, sparse
capability fallback, insufficient concurrency coordination and trace
logging inside measurements. The assertion scan fallback avoids the
discarded candidate's large cold and sparse regressions; its remaining
overhead and dense temporary allocations are disclosed above.

The earlier 16 commits also passed a full 29-package suite, affected race
suites, real SQLite and PostgreSQL collector tests, and Docker integration
scenarios for embedded DERP, ephemeral cleanup, enabling routes and
Hostinfo peer visibility. That Docker build preceded the separate Hostinfo
clone fix, which was subsequently covered by root/state races and a fresh
full suite. Docker was not rerun for the latest four optimizations. The
integration CPU profile was truncated, so no integration profiling claim
is made.

[Review the latest four source commits](https://github.com/kradalby/headscale/compare/d00f135bf151e879c50e2342de1aea475ff62505...e38b62bcf21c3abfe160656499fdf00079a340ec)
or [all 20 source commits](https://github.com/kradalby/headscale/compare/c083a7a1149c0cfb13296a06c32845fa57860444...e38b62bcf21c3abfe160656499fdf00079a340ec).
No PR was opened.
