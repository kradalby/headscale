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
	"slices"
	"strconv"
	"strings"
	"sync"
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
	debugGraphMaxViewers    = 4
	debugGraphRecentScenes  = 8
	// A live stream ends after this and the browser's EventSource
	// reconnects for a new baseline. Heartbeats land in the kernel's send
	// buffer, so a viewer that vanished without closing its connection is
	// noticed only when TCP gives up; until then it holds a viewer slot.
	debugGraphStreamLifetime = time.Minute
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

	g := &debugGraph{
		h: h,
		// Graph revisions restart with the process; wire revisions must not collide.
		instance: rand.Text(),
		viewers:  make(chan struct{}, debugGraphMaxViewers),
	}

	// Details include policy source, filters and SSH rules: use the gate of
	// /debug/policy, not protectedDebugHandler's private-network allowance.
	mux.Handle("GET /debug/graph/", tsweb.Protected(http.StripPrefix("/debug/graph/", http.FileServerFS(static))))
	mux.Handle("GET /debug/graph/logo.svg", tsweb.Protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		http.ServeContent(w, r, "logo.svg", time.Time{}, strings.NewReader(assets.SVG))
	})))
	mux.Handle("GET /debug/graph/favicon.png", tsweb.Protected(http.HandlerFunc(FaviconHandler)))
	mux.Handle("GET /debug/graph/snapshot", tsweb.Protected(sameSiteGraph(g.snapshot)))
	mux.Handle("GET /debug/graph/events", tsweb.Protected(sameSiteGraph(g.events)))
	mux.Handle("GET /debug/graph/detail", tsweb.Protected(sameSiteGraph(g.detail)))
}

// debugGraph serves the explorer's data on one debug listener.
type debugGraph struct {
	h        *Headscale
	instance string
	// viewers admits live streams: each projects its scene up to four times
	// a second, so their number bounds the explorer's CPU cost.
	viewers chan struct{}

	mu sync.Mutex
	// sent retains the snapshots of the latest scenes sent to any viewer:
	// a detail request names the revision its viewer shows, which commits
	// have usually passed by the time it arrives.
	sent [debugGraphRecentScenes]*state.Snapshot
	next int
}

// sameSiteGraph refuses requests a browser marks as sent by another site's
// page. The address gate admits every page open in a browser on the debug
// host, and each graph request costs a projection or a live subscription.
func sameSiteGraph(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" || foreignOrigin(r) {
			http.Error(w, "cross-site graph requests are refused", http.StatusForbidden)
			return
		}

		next(w, r)
	})
}

// foreignOrigin reports a browser request from another host's page, for
// browsers that send no Sec-Fetch-Site: an Origin naming a host other than
// the one requested, or an opaque one.
func foreignOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || r.Header.Get("Sec-Fetch-Site") != "" {
		return false
	}

	u, err := url.Parse(origin)

	return err != nil || u.Host != r.Host
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

	if (query.Perspective != "core" && query.Perspective != "world") ||
		len(query.Search) > debugGraphQueryLimit || len(query.Focus) > debugGraphQueryLimit {
		http.Error(w, "invalid graph query", http.StatusBadRequest)
		return state.DebugGraphQuery{}, false
	}

	return query, true
}

func (g *debugGraph) snapshot(w http.ResponseWriter, r *http.Request) {
	query, ok := debugGraphQuery(w, r)
	if !ok {
		return
	}

	writeGraphJSON(w, g.scene(g.h.state.Snapshot(), query))
}

// scene projects s for a viewer and retains s, so details at the revision
// the viewer shows stay available while commits continue.
func (g *debugGraph) scene(s *state.Snapshot, query state.DebugGraphQuery) state.DebugGraphScene {
	scene := s.DebugGraph(query)
	scene.Revision = g.instance + ":" + scene.Revision

	g.mu.Lock()
	defer g.mu.Unlock()

	if !slices.ContainsFunc(g.sent[:], func(sent *state.Snapshot) bool { return sent != nil && sent.Rev() == s.Rev() }) {
		g.sent[g.next] = s
		g.next = (g.next + 1) % len(g.sent)
	}

	return scene
}

// sentSnapshot returns the snapshot of a revision recently sent, or nil.
func (g *debugGraph) sentSnapshot(rev uint64) *state.Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, s := range g.sent {
		if s != nil && s.Rev() == rev {
			return s
		}
	}

	return nil
}

func (g *debugGraph) detail(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()

	id, revision := values.Get("id"), values.Get("revision")
	if id == "" || len(id) > debugGraphQueryLimit || revision == "" || len(revision) > len(g.instance)+1+20 {
		http.Error(w, "id and revision are required", http.StatusBadRequest)
		return
	}

	instance, graphRevision, hasInstance := strings.Cut(revision, ":")

	rev, err := strconv.ParseUint(graphRevision, 10, 64)
	if !hasInstance || err != nil {
		http.Error(w, "invalid revision", http.StatusBadRequest)
		return
	}

	var snapshot *state.Snapshot
	if instance == g.instance {
		snapshot = g.sentSnapshot(rev)
	}

	if snapshot == nil {
		http.Error(w, "snapshot no longer retained; refresh the scene to inspect current details", http.StatusConflict)
		return
	}

	data, ok := snapshot.DebugGraphDetail(id, g.h.cfg.ServerURL)
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

// events keeps only the last bounded scene sent to this observer.
// The graph's subscription coalesces commits without blocking the writer.
func (g *debugGraph) events(w http.ResponseWriter, r *http.Request) {
	query, ok := debugGraphQuery(w, r)
	if !ok {
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	// The GET pattern also routes HEAD, which has no stream to open.
	if r.Method == http.MethodHead {
		return
	}

	select {
	case g.viewers <- struct{}{}:
		defer func() { <-g.viewers }()
	default:
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many live graph viewers; close one or use a paused snapshot", http.StatusServiceUnavailable)

		return
	}

	sub := g.h.state.Subscribe()
	defer sub.Close()

	previous := g.scene(g.h.state.Snapshot(), query)

	data, err := marshalGraphJSON(previous)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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

	lifetime := time.NewTimer(debugGraphStreamLifetime)
	defer lifetime.Stop()
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
		case <-lifetime.C:
			return
		case <-sub.C:
			if ready == nil {
				timer = time.NewTimer(debugGraphInterval)
				ready = timer.C
			}
		case <-ready:
			ready = nil

			snapshot := g.h.state.Snapshot()
			if g.instance+":"+strconv.FormatUint(snapshot.Rev(), 10) == previous.Revision {
				continue
			}

			next := g.scene(snapshot, query)

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
