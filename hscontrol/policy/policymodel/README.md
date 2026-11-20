# Property tests

`policymodel` is test support: generators for policies, tailnets and edit
scripts ("scenarios"), a plain-reading reference of what a policy grants, and
an oracle that runs Tailscale's own packet filter. It imports nothing from
`policy/v2`, `state` or `mapper`, so it cannot share their bugs.

The properties built on it use [rapid](https://pkg.go.dev/pgregory.net/rapid):

| Where                              | Holds                                                                                            |
| ---------------------------------- | ------------------------------------------------------------------------------------------------ |
| `policy/v2/*_property_test.go`     | The compile's layers: incremental against from scratch, the filter change set, the emitted form  |
| `policy/v2/*reference_test.go`     | Filters, peers, routes and capability form against the reference; the reference against captures |
| `state/world_property_test.go`     | The world against one built from scratch; what `Since` reports                                   |
| `mapper/route_property_test.go`    | Every session a change reaches is woken                                                          |
| `mapper/hub_property_test.go`      | The hub under drawn schedules: coalesced commits, slow and overlapping sessions                  |
| `mapper/delivery_property_test.go` | What a real Tailscale client assembles, in all four option combinations, against the reference   |

## Run

`go test ./...` runs every property on 100 generated cases with a fresh seed.
CI does the same, also under the race detector and with both policy options
off.

```bash
# Deep: more cases, one property
go test ./hscontrol/mapper -run 'TestDeliveryConvergesThroughTheClient$' -rapid.checks=2000

# Reproduce: the failure prints its seed and the minimised case
go test ./hscontrol/mapper -run 'TestDeliveryConvergesThroughTheClient$' -rapid.seed=1234

# Soak: every property, fresh seeds, deep budgets, for hours
tools/pbt-soak.sh . 8 6    # worktree, hours, workers; results in ./pbt-soak/, STOP there ends it
```

| Knob                                                                            | Effect                                                             |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `-rapid.checks=N`                                                               | Cases per property (default 100). From 1000, coverage floors apply |
| `-rapid.seed=N`                                                                 | Replay a run                                                       |
| `-rapid.steps=N`                                                                | Longer scenarios in the stateful properties                        |
| `-rapid.nofailfile`                                                             | Do not write `testdata/rapid/`; rapid replays files it finds there |
| `HEADSCALE_SIDES_SEED`, `HEADSCALE_HUB_SEED`                                    | Replay the clock-seeded tests; a failure prints the value          |
| `HEADSCALE_PBT_DELIVERY_JUDGES`                                                 | Run only the named parts of the delivery property                  |
| `HEADSCALE_PBT_KNOWN_BUGS=1`                                                    | Run the tests pinned to known production bugs; they fail           |
| `HEADSCALE_TEST_CAPABILITY_SOURCES=false`, `HEADSCALE_TEST_FILTER_CHUNKS=false` | Turn a policy option off in tests that follow the default          |

Deep runs of the mapper package need a long `-timeout`.

## When a property fails

1. Rerun with the printed seed. If it does not reproduce, it is a test bug.
2. Minimise by hand and decide which side is wrong: the code, the reference,
   or the generator drawing something headscale cannot reach.
3. Fix the cause. Never widen a tolerance to make a seed pass.

A difference in production that stays for now is pinned, not hidden: a named
clause in `reference.go` or a counted exception in the test, each tagged
`TODO(kradalby): <area>/<key>` at the test and at the code, and held to
production by a hand-built case that fails once production changes.
`git grep 'TODO(kradalby): policy/'` lists them; `overwake/` lists the wakes
that are wider than needed.

## Changing the generators

- Draw only what the API and the client protocol can produce. Database-only
  states (shared or missing addresses) stay rare and labelled.
- Build from rapid's primitives, not `Filter`: cases must shrink.
  `TestShrinksToSmallCases` holds that.
- Every draw moves every later one. After a change, rerun `TestCoverage` and
  the properties on a few hundred fresh seeds.
- A coverage floor must sit far below what any seed draws, or apply to deep
  runs only. A floor that one seed in a thousand misses is a red CI build.
- A new shape is finished when a seeded bug that needs it makes a property
  fail.
