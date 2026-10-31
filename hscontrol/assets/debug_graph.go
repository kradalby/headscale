//go:build headscale_debug

package assets

import "embed"

// DebugGraph contains only the graph explorer's runtime assets.
//
//go:embed debug-graph/index.html debug-graph/app.js debug-graph/style.css debug-graph/elm.js
var DebugGraph embed.FS
