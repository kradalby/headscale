//go:build headscale_debug

package hscontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/juanfont/headscale/hscontrol/assets"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
)

func TestDebugGraphHTTP(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("graph-user")
	node := app.state.CreateRegisteredNodeForTest(user, "graph-laptop")
	app.state.PutNodeInStoreForTest(*node)
	handler := app.debugHTTPServer().Handler

	request := func(path, remote string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.Host = "localhost"
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w
	}

	w := request("/debug/graph/snapshot?perspective=world", "127.0.0.1:1234")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var scene struct {
		Revision string `json:"revision"`
		Vertices []struct {
			ID string `json:"id"`
		} `json:"vertices"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &scene))
	require.NotEmpty(t, scene.Revision)
	assert.Contains(t, w.Body.String(), "graph-laptop")
	assert.NotContains(t, w.Body.String(), "MachineKey")

	// elm.js is a Nix product, and the placeholder linting embeds (or any
	// stray file) would satisfy a non-empty check, so require the compiled
	// application and compare each asset with what is embedded.
	for path, file := range map[string]string{
		"/debug/graph/":          "index.html",
		"/debug/graph/elm.js":    "elm.js",
		"/debug/graph/app.js":    "app.js",
		"/debug/graph/style.css": "style.css",
	} {
		want, err := assets.DebugGraph.ReadFile("debug-graph/" + file)
		require.NoError(t, err, file)

		w = request(path, "127.0.0.1:1234")
		require.Equal(t, http.StatusOK, w.Code, path)
		assert.Equal(t, want, w.Body.Bytes(), "%s must serve the embedded file", path)

		if file == "elm.js" {
			require.Contains(t, string(want), "Elm.Main", "elm.js is not the compiled explorer; run `make debug-graph`")
		}
	}

	w = request("/debug/graph/logo.svg", "127.0.0.1:1234")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "image/svg+xml", w.Header().Get("Content-Type"))
	assert.Equal(t, assets.SVG, w.Body.String())
	w = request("/debug/graph/favicon.png", "127.0.0.1:1234")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "image/png", w.Header().Get("Content-Type"))
	assert.Equal(t, assets.Favicon, w.Body.Bytes())

	w = request("/debug/graph/src/Main.elm", "127.0.0.1:1234")
	assert.Equal(t, http.StatusNotFound, w.Code)

	id := "node:" + strconv.FormatUint(uint64(node.ID), 10)
	detailURL := "/debug/graph/detail?id=" + url.QueryEscape(id) + "&revision=" + scene.Revision
	w = request(detailURL, "127.0.0.1:1234")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "graph-laptop")
	w = request("/debug/graph/detail?id=unknown&revision="+scene.Revision, "127.0.0.1:1234")
	assert.Equal(t, http.StatusNotFound, w.Code)

	app.state.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}})

	w = request(detailURL, "127.0.0.1:1234")
	assert.Equal(t, http.StatusOK, w.Code, "a sent revision outlives the next commit")

	for _, path := range []string{
		"/debug/graph/snapshot?perspective=unknown",
		"/debug/graph/snapshot?search=" + strings.Repeat("x", 513),
		"/debug/graph/detail?id=node:1",
		"/debug/graph/detail?id=node:1&revision=invalid",
		"/debug/graph/detail?id=node:1&revision=instance:not-a-number",
		"/debug/graph/detail?id=node:1&revision=" + strings.Repeat("x", 100),
	} {
		w = request(path, "127.0.0.1:1234")
		assert.Equal(t, http.StatusBadRequest, w.Code, path)
	}

	for _, path := range []string{"/debug/graph/", "/debug/graph/logo.svg", "/debug/graph/favicon.png", "/debug/graph/snapshot", "/debug/graph/events", detailURL} {
		w = request(path, "203.0.113.1:1234")
		assert.Equal(t, http.StatusForbidden, w.Code, path)
	}
}

func TestDebugGraphAccess(t *testing.T) {
	app := createTestApp(t)
	handler := app.debugHTTPServer().Handler
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // An incorrectly admitted SSE request must not hang the test.

	request := func(path, remote string, forwarded bool) *httptest.ResponseRecorder {
		t.Helper()

		r := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		r.Host = "localhost"
		r.RemoteAddr = remote

		if forwarded {
			r.Header.Set("X-Forwarded-For", "203.0.113.1")
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w
	}
	w := request("/debug/graph/snapshot", "127.0.0.1:1234", false)
	require.Equal(t, http.StatusOK, w.Code)

	var scene state.DebugGraphScene

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &scene))

	paths := []string{
		"/debug/graph/", "/debug/graph/app.js", "/debug/graph/elm.js", "/debug/graph/style.css",
		"/debug/graph/logo.svg", "/debug/graph/favicon.png", "/debug/graph/snapshot", "/debug/graph/events",
		"/debug/graph/detail?id=cell:policy-source&revision=" + url.QueryEscape(scene.Revision),
	}

	// The graph serves policy, filters and SSH rules, so it shares the gate
	// of /debug/ssh, not the wider private-network gate of statsviz.
	for _, tc := range []struct {
		remote string
		status int
	}{
		{"127.0.0.1:1234", http.StatusOK},
		{"[::1]:1234", http.StatusOK},
		{"192.168.1.2:1234", http.StatusForbidden},
		{"[fd00::2]:1234", http.StatusForbidden},
	} {
		t.Run(tc.remote, func(t *testing.T) {
			for _, path := range append(paths, "/debug/ssh") {
				assert.Equal(t, tc.status, request(path, tc.remote, false).Code, "direct %s", path)
				assert.Equal(t, http.StatusForbidden, request(path, tc.remote, true).Code, "forwarded %s", path)
			}

			assert.Equal(t, http.StatusOK, request("/debug/statsviz/", tc.remote, false).Code)
		})
	}

	// tsweb's own escape hatch admits exactly one named address, and like the
	// other grants it never applies to a proxied request.
	t.Run("TS_ALLOW_DEBUG_IP", func(t *testing.T) {
		t.Setenv("TS_ALLOW_DEBUG_IP", "192.168.1.2")

		for _, path := range append(paths, "/debug/ssh") {
			assert.Equal(t, http.StatusOK, request(path, "192.168.1.2:1234", false).Code, "named address %s", path)
			assert.Equal(t, http.StatusForbidden, request(path, "192.168.1.3:1234", false).Code, "other private address %s", path)
			assert.Equal(t, http.StatusForbidden, request(path, "192.168.1.2:1234", true).Code, "forwarded %s", path)
		}
	})

	keyPath := t.TempDir() + "/debugkey"
	require.NoError(t, os.WriteFile(keyPath, []byte("graph-debug-key"), 0o600))
	t.Setenv("TS_DEBUG_KEY_PATH", keyPath)
	assert.Equal(t, http.StatusOK, request("/debug/graph/snapshot?debugkey=graph-debug-key", "192.168.1.2:1234", true).Code)
}

func TestDebugGraphIndexLink(t *testing.T) {
	const key = `graph&key+<">`

	keyPath := t.TempDir() + "/debugkey"
	require.NoError(t, os.WriteFile(keyPath, []byte(key), 0o600))
	t.Setenv("TS_DEBUG_KEY_PATH", keyPath)
	handler := createTestApp(t).debugHTTPServer().Handler

	for _, withKey := range []bool{false, true} {
		t.Run(strconv.FormatBool(withKey), func(t *testing.T) {
			request := func(path string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)

				r.Host = "localhost"
				r.RemoteAddr = "127.0.0.1:1234"
				if withKey {
					r.Header.Set("X-Forwarded-For", "203.0.113.1")
				}

				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)

				return w
			}

			query := url.Values{"unrelated": {"keep-private"}}
			if withKey {
				query.Set("debugkey", key)
			}

			index := request("/debug/?" + query.Encode())
			require.Equal(t, http.StatusOK, index.Code)
			link := regexp.MustCompile(`<a href="([^"]*)">/debug/graph/</a>`).FindStringSubmatch(index.Body.String())
			require.Len(t, link, 2)
			target, err := url.Parse(html.UnescapeString(link[1]))
			require.NoError(t, err)
			query.Del("unrelated")
			assert.Equal(t, query, target.Query(), "only the debug key may propagate")
			assert.Equal(t, http.StatusOK, request(target.String()).Code, "index link must retain access")
		})
	}
}

func TestDebugGraphRevisionInstance(t *testing.T) {
	app := createTestApp(t)
	first := httptest.NewServer(app.debugHTTPServer().Handler)
	t.Cleanup(first.Close)

	second := httptest.NewServer(app.debugHTTPServer().Handler)
	t.Cleanup(second.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	snapshot := func(server *httptest.Server) state.DebugGraphScene {
		t.Helper()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/debug/graph/snapshot", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var scene state.DebugGraphScene

		require.NoError(t, json.NewDecoder(resp.Body).Decode(&scene))

		return scene
	}
	before, after := snapshot(first), snapshot(second)
	numericRevision := strconv.FormatUint(app.state.Snapshot().Rev(), 10)
	assert.Equal(t, numericRevision, before.Revision[strings.LastIndex(before.Revision, ":")+1:])
	assert.Equal(t, numericRevision, after.Revision[strings.LastIndex(after.Revision, ":")+1:])
	assert.NotEqual(t, before.Revision, after.Revision, "separate registrations must not reuse wire revisions")
	assert.Equal(t, before.Revision, snapshot(first).Revision, "instance identity must survive requests")

	for _, tc := range []struct {
		name     string
		revision string
		status   int
	}{
		{"current", after.Revision, http.StatusOK},
		// The numeric revision is current, so only the instance check refuses it.
		{"previous instance", before.Revision, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, second.URL+"/debug/graph/detail?id=cell:nodes&revision="+url.QueryEscape(tc.revision), nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			require.Equal(t, tc.status, resp.StatusCode)

			if tc.status == http.StatusOK {
				var detail struct {
					Revision string `json:"revision"`
				}
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&detail))
				assert.Equal(t, after.Revision, detail.Revision)
			}
		})
	}
}

func TestDebugGraphServerShutdown(t *testing.T) {
	app := createTestApp(t)
	server := httptest.NewUnstartedServer(nil)
	server.Config = app.debugHTTPServer()
	handler := server.Config.Handler
	done := make(chan struct{})
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)

		handler.ServeHTTP(w, r)
	})
	server.Start()
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/debug/graph/events", nil)
	require.NoError(t, err)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "event: snapshot\n", line)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	require.NoError(t, server.Config.Shutdown(ctx))

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("graph stream did not stop during server shutdown")
	}

	_, err = io.Copy(io.Discard, reader)
	require.NoError(t, err, "server must end the healthy stream without client cancellation")
}

func TestDebugGraphStream(t *testing.T) {
	app := createTestApp(t)
	done := make(chan struct{})
	handler := app.debugHTTPServer().Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)

		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/debug/graph/events?perspective=world", nil)
	require.NoError(t, err)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 2<<20)

	readEvent := func() (string, map[string]json.RawMessage) {
		t.Helper()

		var event string

		for scanner.Scan() {
			line := scanner.Text()
			if after, ok := strings.CutPrefix(line, "event: "); ok {
				event = after
			}

			if data, ok := strings.CutPrefix(line, "data: "); ok {
				var payload map[string]json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(data), &payload))

				return event, payload
			}
		}

		require.NoError(t, scanner.Err())
		t.Fatal("stream ended before an event")

		return "", nil
	}

	event, baseline := readEvent()
	require.Equal(t, "snapshot", event)

	var baselineRevision string

	require.NoError(t, json.Unmarshal(baseline["revision"], &baselineRevision))
	instance, graphRevision, ok := strings.Cut(baselineRevision, ":")
	require.True(t, ok, "SSE revisions must include the server instance")
	assert.Equal(t, strconv.FormatUint(app.state.Snapshot().Rev(), 10), graphRevision)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/graph/detail?id=cell:nodes&revision="+url.QueryEscape(baselineRevision), nil)
	r.Host = "localhost"
	r.RemoteAddr = "127.0.0.1:1234"
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, "SSE and detail requests must share the instance")

	user := app.state.CreateUserForTest("stream-user")
	node := app.state.CreateRegisteredNodeForTest(user, "stream-laptop")
	app.state.PutNodeInStoreForTest(*node)

	var updated map[string]json.RawMessage
	for {
		event, updated = readEvent()
		require.Equal(t, "patch", event)
		assert.JSONEq(t, string(baseline["revision"]), string(updated["baseRevision"]))

		var revision string

		require.NoError(t, json.Unmarshal(updated["revision"], &revision))
		assert.True(t, strings.HasPrefix(revision, instance+":"), "patch revisions must retain the instance")

		baseline = updated
		if strings.Contains(string(updated["vertices"]), "stream-laptop") {
			break
		}
	}

	app.state.DeleteNodeFromStoreForTest(node.ID)

	event, removed := readEvent()
	require.Equal(t, "patch", event)
	assert.Contains(t, string(removed["removedVertices"]), "node:"+strconv.FormatUint(uint64(node.ID), 10))
	cancel()

	_, err = io.Copy(io.Discard, resp.Body)
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not stop after client cancellation")
	}
}

func TestDebugGraphPatch(t *testing.T) {
	previous := state.DebugGraphScene{
		Revision: "instance:9007199254740993",
		Vertices: []state.DebugGraphVertex{
			{ID: "node:1", Label: "old", Properties: map[string]string{"online": "false"}},
			{ID: "node:2", Label: "removed"},
			{ID: "node:3", Label: "unchanged"},
		},
		Edges: []state.DebugGraphEdge{{ID: "edge:1", Source: "node:1", Target: "node:2", Kind: "visible to"}},
	}
	next := state.DebugGraphScene{
		Revision: "instance:9007199254740994", TotalNodes: 3,
		Vertices: []state.DebugGraphVertex{
			{ID: "node:1", Label: "old", Properties: map[string]string{"online": "true"}},
			{ID: "node:3", Label: "unchanged"},
			{ID: "node:4", Label: "new"},
		},
		Edges: []state.DebugGraphEdge{{ID: "edge:2", Source: "node:1", Target: "node:4", Kind: "visible to"}},
	}
	patch := diffGraphScene(previous, next)
	assert.Equal(t, previous.Revision, patch.BaseRevision)
	assert.Equal(t, next.Revision, patch.Revision)
	require.Len(t, patch.Vertices, 2)
	assert.Equal(t, "node:1", patch.Vertices[0].ID)
	assert.Equal(t, "true", patch.Vertices[0].Properties["online"])
	assert.Equal(t, "node:4", patch.Vertices[1].ID)
	assert.Equal(t, []string{"node:2"}, patch.RemovedVertices)
	assert.Equal(t, []string{"edge:1"}, patch.RemovedEdges)
	require.Len(t, patch.Edges, 1)
	assert.Equal(t, "edge:2", patch.Edges[0].ID)

	encoded, err := json.Marshal(diffGraphScene(next, next))
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"vertices":[]`)
	assert.Contains(t, string(encoded), `"removedEdges":[]`)
}

func TestDebugGraphSlowObserver(t *testing.T) {
	app := createTestApp(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	w := &blockedGraphWriter{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	// Block only this test observer's first flush, not the graph's publisher.
	done := make(chan struct{})
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/debug/graph/events", nil)
	r.Host = "localhost"
	r.RemoteAddr = "127.0.0.1:1234"
	handler := app.debugHTTPServer().Handler

	go func() {
		defer close(done)

		handler.ServeHTTP(w, r)
	}()

	t.Cleanup(func() {
		cancel()
		close(w.release)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("observer did not stop")
		}
	})

	select {
	case <-w.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observer never flushed its baseline")
	}

	committed := make(chan struct{})
	go func() {
		defer close(committed)

		for i := range 20 {
			app.state.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				1: {RegionID: 1, RegionName: strconv.Itoa(i)},
			}})
		}
	}()

	select {
	case <-committed:
	case <-time.After(2 * time.Second):
		t.Fatal("graph writer blocked behind the slow debug observer")
	}
}

type blockedGraphWriter struct {
	*httptest.ResponseRecorder

	entered chan struct{}
	release chan struct{}
}

func (w *blockedGraphWriter) FlushError() error {
	close(w.entered)
	<-w.release

	return context.Canceled
}

func TestDebugGraphCancelBlockedResponse(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "write"
		if buffered {
			name = "flush"
		}

		t.Run(name, func(t *testing.T) {
			app := createTestApp(t)
			ctx, cancel := context.WithCancel(t.Context())
			server, client := net.Pipe()

			w := &pipeGraphWriter{ResponseRecorder: httptest.NewRecorder(), Conn: server}
			if buffered {
				w.buffer = bufio.NewWriterSize(server, 64*1024)
			}

			done := make(chan struct{})

			t.Cleanup(func() {
				cancel()

				_ = server.Close()
				_ = client.Close()

				<-done
			})

			r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/debug/graph/events", nil)
			r.Host = "localhost"
			r.RemoteAddr = "127.0.0.1:1234"
			handler := app.debugHTTPServer().Handler

			go func() {
				defer close(done)

				handler.ServeHTTP(w, r)
			}()

			// Reading one byte leaves the first frame blocked in the pipe.
			require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
			_, err := client.Read(make([]byte, 1))
			require.NoError(t, err)
			cancel()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("request cancellation did not interrupt the blocked response")
			}
		})
	}
}

type pipeGraphWriter struct {
	*httptest.ResponseRecorder
	net.Conn

	buffer *bufio.Writer
}

func (w *pipeGraphWriter) Write(p []byte) (int, error) {
	if w.buffer != nil {
		return w.buffer.Write(p)
	}

	return w.Conn.Write(p)
}

func (w *pipeGraphWriter) FlushError() error {
	if w.buffer != nil {
		return w.buffer.Flush()
	}

	return nil
}

func TestDebugGraphShutdownUnreadFinalChunk(t *testing.T) {
	app := createTestApp(t)
	server := app.debugHTTPServer()
	conn, client := net.Pipe()
	served := make(chan error, 1)
	done := make(chan struct{})
	handler := server.Handler

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)

		r.Host = "localhost"
		r.RemoteAddr = "127.0.0.1:1234"
		handler.ServeHTTP(w, r)
	})
	go func() { served <- server.Serve(netutil.NewOneConnListener(conn, nil)) }()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()

		err := <-served
		if !errors.Is(err, io.EOF) {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost/debug/graph/events", nil)
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, req.Write(client))
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		_ = resp.Body.Close()
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	reader := bufio.NewReader(resp.Body)
	for {
		line, readErr := reader.ReadString('\n')
		require.NoError(t, readErr)

		if line == "\n" {
			break
		}
	}

	// Stop reading between frames, including the final HTTP chunk after return.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)

	select {
	case <-done:
	default:
		t.Fatal("handler did not return on shutdown")
	}

	require.NoError(t, err, "HTTP finalization must also finish within the shutdown budget")
}

// A GET pattern also routes HEAD; the stream must answer it without
// subscribing, since there is no body to stream.
func TestDebugGraphHead(t *testing.T) {
	handler := createTestApp(t).debugHTTPServer().Handler

	for _, tc := range []struct {
		path        string
		contentType string
	}{
		{"/debug/graph/", "text/html; charset=utf-8"},
		{"/debug/graph/app.js", "text/javascript; charset=utf-8"},
		{"/debug/graph/logo.svg", "image/svg+xml"},
		{"/debug/graph/snapshot", "application/json"},
		{"/debug/graph/events", "text/event-stream"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodHead, tc.path, nil)
			r.Host = "localhost"
			r.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			done := make(chan struct{})

			go func() {
				defer close(done)

				handler.ServeHTTP(w, r)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("HEAD did not return")
			}

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.contentType, w.Header().Get("Content-Type"))
		})
	}
}

// The address gate admits any page open in a browser on the debug host;
// Sec-Fetch-Site tells the server a request came from another site.
// TestDebugGraphRefusesForeignOrigin covers browsers that send no
// Sec-Fetch-Site: an Origin naming another host is refused, one naming the
// listener's host, or none (curl, a typed URL), is admitted.
func TestDebugGraphRefusesForeignOrigin(t *testing.T) {
	handler := createTestApp(t).debugHTTPServer().Handler

	request := func(origin string) int {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/graph/snapshot", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Host = "127.0.0.1:9090"

		if origin != "" {
			r.Header.Set("Origin", origin)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w.Code
	}

	assert.Equal(t, http.StatusForbidden, request("https://attacker.example"), "another host's page")
	assert.Equal(t, http.StatusForbidden, request("null"), "an opaque origin")
	assert.Equal(t, http.StatusOK, request("http://127.0.0.1:9090"), "the explorer's own page")
	assert.Equal(t, http.StatusOK, request(""), "no browser origin")
}

func TestDebugGraphRefusesCrossSite(t *testing.T) {
	app := createTestApp(t)
	handler := app.debugHTTPServer().Handler
	revision := "x:" + strconv.FormatUint(app.state.Snapshot().Rev(), 10)

	request := func(path, site string) int {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.Host = "localhost"
		r.RemoteAddr = "127.0.0.1:1234"

		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}

		w := httptest.NewRecorder()
		done := make(chan struct{})

		go func() {
			defer close(done)

			handler.ServeHTTP(w, r)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s from %q was admitted to the stream", path, site)
		}

		return w.Code
	}

	for _, path := range []string{"/debug/graph/snapshot", "/debug/graph/events", "/debug/graph/detail?id=cell:nodes&revision=" + revision} {
		assert.Equal(t, http.StatusForbidden, request(path, "cross-site"), path)
	}

	for _, site := range []string{"", "none", "same-origin", "same-site"} {
		assert.Equal(t, http.StatusOK, request("/debug/graph/snapshot", site), site)
	}
}

// Each live viewer projects the scene up to four times a second, so the
// stream admits a bounded number; snapshots stay available.
// TestDebugGraphStreamLifetimeFreesItsSlot opens a live stream nobody
// reads or closes, as a vanished browser leaves one: the stream must end
// within its lifetime, releasing its viewer slot, on a fake clock.
func TestDebugGraphStreamLifetimeFreesItsSlot(t *testing.T) {
	// Outside the bubble: the debug server starts goroutines of its own.
	handler := createTestApp(t).debugHTTPServer().Handler

	synctest.Test(t, func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/graph/events", nil)
		req.Host = "localhost"
		req.RemoteAddr = "127.0.0.1:41641"
		rec := httptest.NewRecorder()

		done := make(chan struct{})

		go func() {
			handler.ServeHTTP(rec, req)
			close(done)
		}()

		<-time.After(debugGraphStreamLifetime - time.Second)
		synctest.Wait()

		select {
		case <-done:
			t.Fatalf("the stream ended before its lifetime: %d %s", rec.Code, rec.Body.String())
		default:
		}

		<-time.After(2 * time.Second)
		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("a stream nobody reads outlives its lifetime and keeps its viewer slot")
		}

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "event: snapshot", "the stream was admitted")
	})
}

func TestDebugGraphViewerLimit(t *testing.T) {
	handler := createTestApp(t).debugHTTPServer().Handler
	returned := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)

		returned <- struct{}{}
	}))
	t.Cleanup(server.Close)

	client := &http.Client{Timeout: 10 * time.Second}
	// Streams stay open until cancelled, so the body closes at cleanup.
	get := func(path string) (int, http.Header, context.CancelFunc) {
		t.Helper()

		ctx, cancel := context.WithCancel(t.Context())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			cancel()

			_ = resp.Body.Close()
		})

		return resp.StatusCode, resp.Header, cancel
	}
	// The documented limit, written out so a changed constant fails here.
	const wantViewers = 4

	require.Equal(t, wantViewers, debugGraphMaxViewers)

	cancels := make([]context.CancelFunc, 0, wantViewers)

	for i := 1; i <= wantViewers; i++ {
		code, _, cancel := get("/debug/graph/events")
		require.Equal(t, http.StatusOK, code, "viewer %d of %d is admitted", i, wantViewers)

		cancels = append(cancels, cancel)
	}

	code, header, _ := get("/debug/graph/events")
	assert.Equal(t, http.StatusServiceUnavailable, code, "viewer %d is refused", wantViewers+1)
	assert.NotEmpty(t, header.Get("Retry-After"))
	<-returned

	code, _, _ = get("/debug/graph/snapshot")
	assert.Equal(t, http.StatusOK, code)
	<-returned

	cancels[0]()
	<-returned

	code, _, _ = get("/debug/graph/events")
	assert.Equal(t, http.StatusOK, code, "a closed viewer frees its place")
}

// A viewer asks for details at the revision it shows, which commits have
// usually passed by the time it asks.
func TestDebugGraphDetailAfterChurn(t *testing.T) {
	app := createTestApp(t)
	handler := app.debugHTTPServer().Handler
	setRegions := func(n int) {
		regions := map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}
		for i := 1; i <= n; i++ {
			regions[tailcfg.DERPRegionID(i)] = &tailcfg.DERPRegion{RegionID: tailcfg.DERPRegionID(i), RegionName: strconv.Itoa(i)}
		}

		app.state.SetDERPMap(&tailcfg.DERPMap{Regions: regions})
	}
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.Host = "localhost"
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		return w
	}
	snapshot := func() state.DebugGraphScene {
		t.Helper()

		w := get("/debug/graph/snapshot")
		require.Equal(t, http.StatusOK, w.Code)

		var scene state.DebugGraphScene

		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &scene))

		return scene
	}
	summary := func(revision string) (int, string) {
		t.Helper()

		w := get("/debug/graph/detail?id=cell:derp-map&revision=" + url.QueryEscape(revision))
		if w.Code != http.StatusOK {
			return w.Code, ""
		}

		var detail struct {
			Revision string `json:"revision"`
			Data     struct {
				Cell state.DebugGraphVertex `json:"cell"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &detail))
		assert.Equal(t, revision, detail.Revision)

		return w.Code, detail.Data.Cell.Summary
	}

	setRegions(0)

	shown := snapshot()
	instance, rev, _ := strings.Cut(shown.Revision, ":")
	sent, err := strconv.ParseUint(rev, 10, 64)
	require.NoError(t, err)

	setRegions(1)
	setRegions(2)
	require.Greater(t, app.state.Snapshot().Rev(), sent+1)

	code, got := summary(shown.Revision)
	require.Equal(t, http.StatusOK, code)

	for _, v := range shown.Vertices {
		if v.ID == "cell:derp-map" {
			assert.Equal(t, v.Summary, got, "details come from the revision shown, not the current one")
		}
	}

	code, _ = summary(instance + ":" + strconv.FormatUint(sent+1, 10))
	assert.Equal(t, http.StatusConflict, code, "a revision never sent was never retained")

	for i := range debugGraphRecentScenes {
		snapshot()
		setRegions(3 + i)
	}

	code, _ = summary(shown.Revision)
	assert.Equal(t, http.StatusConflict, code, "retention is bounded")
}
