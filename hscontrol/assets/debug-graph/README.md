# Debug graph frontend

This Elm/SVG application is served locally at `/debug/graph/` on the debug build's
metrics/debug listener. See [operator documentation](../../../docs/ref/debug.md)
for access details. No remote scripts, fonts or runtime package
downloads are required.

## Build and verify

Build the debug binary from the repository root:

```sh
nix build .#headscale-debug
./result/bin/headscale serve
```

Nix builds the existing `.#debug-graph` Elm derivation first (or uses its cached
output), copies the result into the Go build, and embeds it with the
`headscale_debug` build tag. The debug package overrides the normal Go package
and shares its toolchain and vendor derivation. It remains optimized; the name
selects the graph feature, not debugger compiler flags.

Normal `nix build`, Docker/release builds and plain `go build` omit the graph
handlers, inspection code and graph assets. They need no Elm output. Existing
metrics, profiling and raw debug endpoints remain available. Nix is the supported
way to build the debug binary; no runtime asset directory is required.

The frontend check validates Elm formatting and runs `bridge-check.js` against `app.js` and
`index.html` using Node's built-in assertions and a simulated browser, covering
stream lifecycle, stale requests and protected asset loading.
The package also compiles `src/FrontendCheck.elm` and runs its checks with the
flake-pinned Node.js before installing the asset.

Checks (Linux example):

```sh
nix build .#checks.x86_64-linux.debug-graph .#checks.x86_64-linux.debug-build .#checks.x86_64-linux.debug-gotest --no-link
nix build .#checks.x86_64-linux.golangci-lint --no-link
```

The package contains `elm.js` at its root. Its compilation inputs contain only
`elm.json` and `src/`; an existing compiled asset or local `elm-stuff` cache
cannot affect the result. Nix fetches hash-pinned dependencies first, then the
compiler builds offline in the sandbox using the checked-in registry. The first
build needs network access unless those dependencies and tools are already in
the Nix store. With them cached, `nix build --offline .#debug-graph` also works.

New source and lock files must be tracked by Git before flake builds can see
them. Generated `elm.js` is ignored and must not be committed or formatted.

For focused Go development tests, prepare the ignored local asset through Nix:

```sh
make debug-graph
go test -tags=headscale_debug ./hscontrol ./hscontrol/state ./hscontrol/graph -run 'Test(DebugGraph|Inspect)'
```

Run untagged tests too: they check that normal builds omit graph routes and the
debug index link. The Nix lint check covers both tag configurations.

## Toolchain and dependency changes

`flake.lock` pins Elm (currently 0.19.2), elm-format and Cachix elm2nix (0.4.0).
The dedicated shell avoids loading the full Go development environment:

```sh
nix develop .#debug-graph
cd hscontrol/assets/debug-graph
elm-format src --yes
```

After changing dependency versions in `elm.json`, refresh both lock files using
the pinned [elm2nix procedure](https://github.com/cachix/elm2nix#readme):

```sh
elm2nix convert > elm-srcs.nix
elm2nix snapshot
nixfmt elm-srcs.nix
```

Run these commands from this directory, inside the shell. Conversion requires
network access to hash package sources. Keep `elm.json`, `elm-srcs.nix` and
`registry.dat` together. `default.nix` is maintained here using nixpkgs'
`elmPackages.fetchElmDeps`; do not overwrite it with `elm2nix init`. Return to
the repository root, rebuild and run the frontend check. When updating the flake
pin, check the compiler version against `elm.json` before regenerating assets.

The UI deliberately shows bounded scenes (200 vertices, 1,000 edges) and optional
live state at at most four updates per second. It is not recommended for large
installations and does not retain an event history. Each scene scans the node
list outside the writer lock, up to four times per second per live viewer;
export cost grows with tailnet size and active viewers even when few nodes
change. Search and focus are limited to 512 bytes each, and responses to 2 MiB;
oversized scenes or details return an error.

World's optional force layout runs 32 Elm steps on request, yielding between
steps, then spaces visible cards without moving pinned objects. Pairwise
repulsion is quadratic in the visible object count and intended for the bounded
debug scene. Camera actions cancel pending settling; live updates do not
automatically restart it. No additional layout dependency is required.
