//go:build headscale_debug

package assets

import "embed"

// DebugGraph contains only the graph explorer's runtime assets. elm.js is a
// Nix build product, never committed: outside Nix, run `make debug-graph`
// before building with -tags=headscale_debug.
//
//go:embed debug-graph/index.html debug-graph/app.js debug-graph/style.css debug-graph/elm.js
var DebugGraph embed.FS
