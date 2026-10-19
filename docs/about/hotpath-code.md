# Current and original hot-path code

These source links are pinned to the measured commit
[`e38b62bcf`](https://github.com/kradalby/headscale/commit/e38b62bcf21c3abfe160656499fdf00079a340ec),
so they remain stable as the review branch changes. See the
[benchmark results and validation](hotpath-benchmarks.md) and
[all optimizations and tradeoffs](hotpath-tradeoffs.md).

| Path                 | Current code                                                                                                                                            | Preserved original                                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capability snapshots | [buildTailPeers](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/mapper/builder.go#L251)                  | [buildTailPeersCapMapsReference](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/mapper/mapper_test.go#L1770)             |
| Capability selection | [NodeCapMapsForPeers](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/policy/v2/policy.go#L2213)          | [nodeCapMapsReference](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/policy/v2/policy_test.go#L3839)                    |
| SSH compilation      | [compileSSHPolicy](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/policy/v2/filter.go#L258)              | [compileSSHPolicyReference](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/policy/v2/filter_test.go#L4275)               |
| DNS updates          | [updateRecords](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/dns/extrarecords.go#L185)                 | [updateRecordsOriginal](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/dns/extrarecords_shutdown_test.go#L423)           |
| Visibility assertion | [AssertSymmetricVisibility](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/servertest/assertions.go#L32) | [assertSymmetricVisibilityReference](https://github.com/kradalby/headscale/blob/e38b62bcf21c3abfe160656499fdf00079a340ec/hscontrol/servertest/consistency_test.go#L166) |

The selector takes one coherent policy read and may return a superset when
a bulk copy is cheaper. SSH memoization lasts one compilation; principal
objects are cloned per input rule. DNS reuses only accepted raw-byte
hashes. Assertion indexes are local to one call and check each publication
generation; small cases retain scans.

The [tradeoffs table](hotpath-tradeoffs.md) links each of the earlier
optimizations to its individual commit, including the preserved original,
differential tests, benchmarks and measured costs.
