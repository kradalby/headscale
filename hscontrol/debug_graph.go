//go:build headscale_debug

package hscontrol

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/assets"
	"github.com/juanfont/headscale/hscontrol/state"
	"tailscale.com/tsweb"
)

const (
	debugGraphInterval      = 250 * time.Millisecond
	debugGraphHeartbeat     = 15 * time.Second
	debugGraphWriteTimeout  = 10 * time.Second
	debugGraphQueryLimit    = 512
	debugGraphResponseLimit = 2 << 20
)

var errDebugGraphTooLarge = errors.New("graph response exceeds 2 MiB; narrow the scene")

func (h *Headscale) registerDebugGraph(mux *http.ServeMux, debug *tsweb.DebugHandler, server *http.Server) {
	debug.Section(func(w io.Writer, r *http.Request) {
		link := "/debug/graph/"
		if key := r.URL.Query().Get("debugkey"); key != "" {
			link += "?debugkey=" + url.QueryEscape(key)
		}

		_, _ = fmt.Fprintf(w, `<li><a href="%s">/debug/graph/</a> (Graph explorer for small installations)</li>`, html.EscapeString(link))
	})

	// Cancel long-lived streams before shutdown waits for handlers.
	ctx, cancel := context.WithCancel(context.Background())
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.RegisterOnShutdown(cancel)

	static, err := fs.Sub(assets.DebugGraph, "debug-graph")
	if err != nil {
		panic(err) // the embedded directory is fixed at build time
	}

	// Graph revisions restart with the process; wire revisions must not collide.
	instance := rand.Text()

	mux.Handle("GET /debug/graph/", protectedDebugHandler(http.StripPrefix("/debug/graph/", http.FileServerFS(static))))
	mux.Handle("GET /debug/graph/logo.svg", protectedDebugHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		http.ServeContent(w, r, "logo.svg", time.Time{}, strings.NewReader(assets.SVG))
	})))
	mux.Handle("GET /debug/graph/favicon.png", protectedDebugHandler(http.HandlerFunc(FaviconHandler)))
	mux.Handle("GET /debug/graph/snapshot", protectedDebugHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.debugGraphSnapshot(w, r, instance)
	})))
	mux.Handle("GET /debug/graph/events", protectedDebugHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.debugGraphEvents(w, r, instance)
	})))
	mux.Handle("GET /debug/graph/detail", protectedDebugHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.debugGraphDetail(w, r, instance)
	})))
}

func debugGraphQuery(w http.ResponseWriter, r *http.Request) (state.DebugGraphQuery, bool) {
	values := r.URL.Query()

	query := state.DebugGraphQuery{
		Perspective: values.Get("perspective"),
		Search:      values.Get("search"),
		Focus:       values.Get("focus"),
	}
	if query.Perspective == "" {
		query.Perspective = "core"
	}

	if query.Perspective != "core" && query.Perspective != "world" ||
		len(query.Search) > debugGraphQueryLimit || len(query.Focus) > debugGraphQueryLimit {
		http.Error(w, "invalid graph query", http.StatusBadRequest)
		return state.DebugGraphQuery{}, false
	}

	return query, true
}

func (h *Headscale) debugGraphSnapshot(w http.ResponseWriter, r *http.Request, instance string) {
	query, ok := debugGraphQuery(w, r)
	if !ok {
		return
	}

	scene := h.state.Snapshot().DebugGraph(query)
	scene.Revision = instance + ":" + scene.Revision
	writeGraphJSON(w, scene)
}

func (h *Headscale) debugGraphDetail(w http.ResponseWriter, r *http.Request, instance string) {
	values := r.URL.Query()

	id, revision := values.Get("id"), values.Get("revision")
	if id == "" || len(id) > debugGraphQueryLimit || revision == "" || len(revision) > len(instance)+1+20 {
		http.Error(w, "id and revision are required", http.StatusBadRequest)
		return
	}

	_, graphRevision, hasInstance := strings.Cut(revision, ":")

	_, err := strconv.ParseUint(graphRevision, 10, 64)
	if !hasInstance || err != nil {
		http.Error(w, "invalid revision", http.StatusBadRequest)
		return
	}

	snapshot := h.state.Snapshot()
	if revision != instance+":"+strconv.FormatUint(snapshot.Rev(), 10) {
		http.Error(w, "snapshot changed; refresh the scene to inspect current details", http.StatusConflict)
		return
	}

	data, ok := snapshot.DebugGraphDetail(id, h.cfg.ServerURL)
	if !ok {
		http.NotFound(w, r)
		return
	}

	writeGraphJSON(w, struct {
		Revision string `json:"revision"`
		ID       string `json:"id"`
		Data     any    `json:"data"`
	}{Revision: revision, ID: id, Data: data})
}

func marshalGraphJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	if len(data) > debugGraphResponseLimit {
		return nil, errDebugGraphTooLarge
	}

	return data, nil
}

func writeGraphJSON(w http.ResponseWriter, value any) {
	data, err := marshalGraphJSON(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data) //nolint:gosec // G705: encoding/json escapes HTML; response is application/json with nosniff.
}

// debugGraphEvents keeps only the last bounded scene sent to this observer.
// The graph's subscription coalesces commits without blocking the writer.
func (h *Headscale) debugGraphEvents(w http.ResponseWriter, r *http.Request, instance string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	query, ok := debugGraphQuery(w, r)
	if !ok {
		return
	}

	sub := h.state.Subscribe()
	defer sub.Close()

	previous := h.state.Snapshot().DebugGraph(query)
	previous.Revision = instance + ":" + previous.Revision

	data, err := marshalGraphJSON(previous)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	control := http.NewResponseController(w)
	// Cancellation must interrupt a blocked write before the shutdown deadline.
	canceled := make(chan struct{})

	stop := context.AfterFunc(r.Context(), func() {
		defer close(canceled)

		_ = control.SetWriteDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-canceled
		}

		// Bound net/http's final chunk while allowing healthy streams to finish.
		_ = control.SetWriteDeadline(time.Now().Add(time.Second))
	}()

	err = writeGraphEvent(r.Context(), w, control, "snapshot", data)
	if err != nil {
		return
	}

	heartbeat := time.NewTicker(debugGraphHeartbeat)
	defer heartbeat.Stop()
	// A timer is only armed after a wake-up; idle observers do no projection work.
	var (
		timer *time.Timer
		ready <-chan time.Time
	)

	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.C:
			if ready == nil {
				timer = time.NewTimer(debugGraphInterval)
				ready = timer.C
			}
		case <-ready:
			ready = nil

			snapshot := h.state.Snapshot()
			if instance+":"+strconv.FormatUint(snapshot.Rev(), 10) == previous.Revision {
				continue
			}

			next := snapshot.DebugGraph(query)
			next.Revision = instance + ":" + next.Revision

			data, err := marshalGraphJSON(diffGraphScene(previous, next))
			if err != nil {
				return
			}

			err = writeGraphEvent(r.Context(), w, control, "patch", data)
			if err != nil {
				return
			}

			previous = next
		case <-heartbeat.C:
			err := control.SetWriteDeadline(time.Now().Add(debugGraphWriteTimeout))
			if err != nil && !errors.Is(err, http.ErrNotSupported) {
				return
			}

			if r.Context().Err() != nil {
				return
			}

			_, err = fmt.Fprint(w, ": heartbeat\n\n")
			if err != nil {
				return
			}

			err = control.Flush()
			if err != nil {
				return
			}
		}
	}
}

func writeGraphEvent(ctx context.Context, w http.ResponseWriter, control *http.ResponseController, event string, data []byte) error {
	err := control.SetWriteDeadline(time.Now().Add(debugGraphWriteTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}

	err = ctx.Err()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data) //nolint:gosec // G705: JSON-encoded event data, fixed event names, text/event-stream and nosniff.
	if err != nil {
		return err
	}

	return control.Flush()
}

type debugGraphPatch struct {
	BaseRevision    string                   `json:"baseRevision"`
	Revision        string                   `json:"revision"`
	Timestamp       string                   `json:"timestamp"`
	Vertices        []state.DebugGraphVertex `json:"vertices"`
	Edges           []state.DebugGraphEdge   `json:"edges"`
	RemovedVertices []string                 `json:"removedVertices"`
	RemovedEdges    []string                 `json:"removedEdges"`
	TotalNodes      int                      `json:"totalNodes"`
	MatchedNodes    int                      `json:"matchedNodes"`
	ShownNodes      int                      `json:"shownNodes"`
	Limit           int                      `json:"limit"`
	Truncated       bool                     `json:"truncated"`
	PolicyError     string                   `json:"policyError"`
}

func diffGraphScene(previous, next state.DebugGraphScene) debugGraphPatch {
	patch := debugGraphPatch{
		BaseRevision: previous.Revision, Revision: next.Revision, Timestamp: next.Timestamp,
		Vertices: []state.DebugGraphVertex{}, Edges: []state.DebugGraphEdge{},
		RemovedVertices: []string{}, RemovedEdges: []string{},
		TotalNodes: next.TotalNodes, MatchedNodes: next.MatchedNodes, ShownNodes: next.ShownNodes,
		Limit: next.Limit, Truncated: next.Truncated, PolicyError: next.PolicyError,
	}

	vertices := make(map[string]state.DebugGraphVertex, len(previous.Vertices))
	for _, vertex := range previous.Vertices {
		vertices[vertex.ID] = vertex
	}

	for _, vertex := range next.Vertices {
		if old, ok := vertices[vertex.ID]; !ok || !reflect.DeepEqual(old, vertex) {
			patch.Vertices = append(patch.Vertices, vertex)
		}

		delete(vertices, vertex.ID)
	}

	for _, vertex := range previous.Vertices {
		if _, removed := vertices[vertex.ID]; removed {
			patch.RemovedVertices = append(patch.RemovedVertices, vertex.ID)
		}
	}

	edges := make(map[string]state.DebugGraphEdge, len(previous.Edges))
	for _, edge := range previous.Edges {
		edges[edge.ID] = edge
	}

	for _, edge := range next.Edges {
		if old, ok := edges[edge.ID]; !ok || old != edge {
			patch.Edges = append(patch.Edges, edge)
		}

		delete(edges, edge.ID)
	}

	for _, edge := range previous.Edges {
		if _, removed := edges[edge.ID]; removed {
			patch.RemovedEdges = append(patch.RemovedEdges, edge.ID)
		}
	}

	return patch
}
