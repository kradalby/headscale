//go:build !headscale_debug

package hscontrol

import (
	"net/http"

	"tailscale.com/tsweb"
)

func (*Headscale) registerDebugGraph(*http.ServeMux, *tsweb.DebugHandler, *http.Server) {}
