# Property tests

The property tests drive headscale from a model and hold what it does to
judges that share no code with it. They are built from three kinds of part,
each written once:

- **Scenarios**: a start world (policy, users, nodes) and steps of edits,
  drawn by `policymodel` (`Worlds`, `Steps`, `Scenarios`). Every level draws
  from these.
- **Levels**: the system at one depth, driven by the model's steps. A level is
  a small adapter: it writes a step the way that depth is written, knows when
  it has settled, and says what it could not write.
- **Judges**: what a level serves, held to the reference (`policymodel`'s
  plain reading of a policy) through Tailscale's own client code, and what it
  stored, held to the model.

So the same scenario and the same judge run against the policy alone, the
world, the State with its hub and sessions, or the whole server.

## The parts

`policymodel` imports nothing from `policy/v2`, `state`, `mapper` or
`servertest`, so it cannot share their bugs. Judges that read production
types sit in `state/statemodel`, which both deep levels import.

| Part          | Where                                                                                       | What                                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Generators    | `policymodel`: `gen.go`, `edit.go`, `topology.go`, `shapes.go` and the shape files          | Policies, tailnets, edits, scenarios; `Required` names every shape they must reach                                          |
| Reference     | `policymodel`: `reference.go`, `served.go`, `sessions.go` (`Elections`)                     | Filters, peers, routes after elections, stamps, as the documentation reads                                                  |
| Client oracle | `policymodel`: `client.go`, `views.go`, `judge.go` (`Verdicts`), `capform.go` (`FormJudge`) | Tailscale's packet filter, the view a client filters with, the contested clauses                                            |
| Client judges | `policymodel/held.go`                                                                       | `NetmapDiff`: a client's netmap against a fresh session's; `HeldJudge`: against the reference; `ModelView` and `NetmapView` |
| Stored judges | `state/statemodel`                                                                          | `Stored`: nodes, users and rows against the model; `Joined`; `ElectionNodes`                                                |
| The seam      | `state/statemodel/level.go`                                                                 | `Level`: model, State, how each node joined, election history                                                               |
| Slices        | `policymodel/slice.go`                                                                      | Run some judges over some shapes (below)                                                                                    |

## The levels

| Level                | Driver                                                                                                          | Properties                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Policy               | `serve`, `drive` (`policy/v2/reference_test.go`)                                                                | `policy/v2/*_property_test.go`, `*reference_test.go`: the compile's layers, filters, peers, routes, form and stamps against the reference    |
| World                | `modelWorld` (`state/world_property_test.go`)                                                                   | The world against one built from scratch; what `Since` reports                                                                               |
| State, hub, sessions | `pbtWorld` (`mapper/route_property_test.go`, `entry_property_test.go`), sessions in `delivery_property_test.go` | `route`: every session a change reaches is woken; `hub`: drawn schedules; `delivery`: real Tailscale clients in all four option combinations |
| Server               | `frontDoor` (`servertest/frontdoor_property_test.go`)                                                           | Real clients through registration, the long poll, the admin API, restarts                                                                    |

The two deep levels are `statemodel.Level`s, and every judge that can is
shared between them: what each client holds goes to `NetmapDiff` against a
fresh session of its node, then to `HeldJudge.At(moment).Client`; what the
State stored goes to `statemodel.Stored`. They differ where the depth does:

- **IDs and addresses.** `pbtWorld` steers production to the model's
  (`steerID`, `nextAddr`) and stores what no entry point can write (a moved
  address, a cleared endpoint) into the row and the world, counted. The
  front door takes what the server hands out and renumbers the model; what it
  cannot write it leaves out of the model, counted.
- **Readiness.** `pbtWorld` calls the State directly and routes the hub with
  a stepped watcher, so a step is settled when its calls return. The server
  is settled when its goroutines are (`quiet` in `frontdoor_judge_test.go`).
- **What only one sees.** Delivery holds four worlds at once (combinations,
  the chunk model, the wire, the address index, SSH from scratch); the front
  door holds registrations' answers, restarts and the admin API.

The order of writes when a node joins is the same at both: registration,
announcing its routes only when no approval must come first; an admin's tags
where a login brought a tagged node in; the admin's approvals of what
auto-approval does not give, before the client announces, so that
auto-approval then adds what the model counts as its own; the announcement;
an admin's expiry; the first map session.

The policy and world levels read cells, not netmaps; they share the oracle
(`Verdicts`, `FormJudge`, `ContestedPeers`, `ModelView`) but not the seam.
`graph/*_property_test.go` holds the graph package to a model that recomputes
from scratch, and `Map` to plain maps; it imports nothing of headscale's
policy or state, by design.

## Adding

- **A judge of what a client holds** (Tailscale types, the model, the
  reference): a method on `Held` in `held.go`, listed in `Held.Client`. Both
  deep levels run it.
- **A judge of what is stored**: in `statemodel.Stored`. Both deep levels run
  it.
- **A level**: implement `statemodel.Level`; after each settled step, call
  `statemodel.Stored`, then for each client `NetmapDiff` against a fresh
  session and `HeldJudge.At(statemodel.Moment(level)).Client`. Read a slice
  with `policymodel.SliceOf(judges...)`.
- **A shape**: a row in `Required` (or the scale and prone tables), drawn
  from rapid's primitives (see below); it is a family a slice can name.

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
# Smoke: every deep invocation once, its checks capped, proving the runner still works
PBT_SOAK_SMOKE=1 tools/pbt-soak.sh .
```

CI runs both (`.github/workflows/pbt-soak.yml`): a nightly soak for
about an hour on the default branch, and the smoke on every pull request
that touches the property layer or the code it tests. The runner exits
non-zero when any run failed.

A slice runs one judge at one level over one family of shapes, from the
property's own code: judges left out are not run, and a case without the
shapes is dropped before the level is driven. A slice holds no floors.

```bash
# The reference alone, at the server, over worlds with a via grant
HEADSCALE_PBT_JUDGES=reference HEADSCALE_PBT_SHAPES=via-grant \
  go test ./hscontrol/servertest -run 'TestFrontDoorClientsFollowTheModel$' -rapid.checks=300 -rapid.nofailfile

# The same judge at the State with its sessions, over every via shape
HEADSCALE_PBT_JUDGES=reference HEADSCALE_PBT_SHAPES='via-*' \
  go test ./hscontrol/mapper -run 'TestDeliveryConvergesThroughTheClient$' -rapid.nofailfile

# The policy alone, over exit nodes
HEADSCALE_PBT_SHAPES=exit-node go test ./hscontrol/policy/v2 -run 'FollowReference$' -rapid.nofailfile
```

Delivery's judges are `client`, `model`, `wire`, `churn`, `kept`, `combos`,
`reference`, `index`, `stored`; the front door's `stored`, `client`,
`reference`, `restart`. The front door draws its steps as it plays, so only
shapes of its start world can select its cases.

| Knob                                                                            | Effect                                                                                           |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `-rapid.checks=N`                                                               | Cases per property (default 100). From 1000, coverage floors apply                               |
| `-rapid.seed=N`                                                                 | Replay a run                                                                                     |
| `-rapid.steps=N`                                                                | Longer scenarios in the stateful properties                                                      |
| `-rapid.nofailfile`                                                             | Do not write `testdata/rapid/`; rapid replays files it finds there                               |
| `HEADSCALE_SIDES_SEED`, `HEADSCALE_HUB_SEED`                                    | Replay the clock-seeded tests; a failure prints the value                                        |
| `HEADSCALE_PBT_JUDGES`, `HEADSCALE_PBT_SHAPES`                                  | Run a slice: the named judges, over cases holding one of the named shapes (`via-*` for a prefix) |
| `HEADSCALE_PBT_KNOWN_BUGS=1`                                                    | Run the tests pinned to known production bugs; they fail                                         |
| `HEADSCALE_TEST_CAPABILITY_SOURCES=false`, `HEADSCALE_TEST_FILTER_CHUNKS=false` | Turn a policy option off in tests that follow the default                                        |

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

A judge forgives a difference only where the reference less every clause is
production exactly, so each clause must restate headscale beside all the
others. A failure that names clauses "restated inexactly" is one that does
not: fix that clause's restatement, never the judge.

## Changing the generators

- Draw only what the API and the client protocol can produce. Database-only
  states (addresses outside the tailnet or moved) stay rare and labelled.
  What the server refuses at startup (two nodes on one address, a node
  without one) is never drawn; `TestGeneratedWorldsStart` in `state` holds
  that.
- Build from rapid's primitives, not `Filter`: cases must shrink.
  `TestShrinksToSmallCases` holds that.
- Every draw moves every later one. After a change, rerun `TestCoverage` and
  the properties on a few hundred fresh seeds.
- Draw a script's chance before the lists a shrink can shorten: a shift
  there can switch on a script that fails a property alone, which the
  shrinker then cannot take out.
- A coverage floor must sit far below what any seed draws, or apply to deep
  runs only. A floor that one seed in a thousand misses is a red CI build.
- A new shape is finished when a seeded bug that needs it makes a property
  fail.
