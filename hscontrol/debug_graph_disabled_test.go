//go:build !headscale_debug

package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebugGraphUnavailable(t *testing.T) {
	handler := createTestApp(t).debugHTTPServer().Handler
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // A mistakenly registered event stream must not block the test.

	for _, path := range []string{
		"/debug/graph/", "/debug/graph/elm.js", "/debug/graph/app.js", "/debug/graph/style.css",
		"/debug/graph/logo.svg", "/debug/graph/favicon.png", "/debug/graph/snapshot",
		"/debug/graph/detail", "/debug/graph/events",
	} {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, http.StatusNotFound, w.Code, path)
	}

	for _, path := range []string{"/debug/", "/metrics", "/debug/overview"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code, path)
		assert.NotContains(t, w.Body.String(), "/debug/graph/")
	}
}
