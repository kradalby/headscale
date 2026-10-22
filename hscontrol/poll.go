package hscontrol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

const (
	keepAliveInterval = 50 * time.Second

	// stopWriteGrace is how long a stopped session's write in flight may
	// take to finish before its stream is reset.
	stopWriteGrace = 5 * time.Second
)

// errMapSessionStopped is a write refused because the session was stopped;
// the poll loop ends as if it had seen cancelCh.
var errMapSessionStopped = errors.New("map session stopped")

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

var errServerShuttingDown = NewHTTPError(http.StatusServiceUnavailable, "server shutting down", nil)

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context //nolint:containedctx
	capVer tailcfg.CapabilityVersion

	cancelCh       chan struct{}
	cancelChClosed atomic.Bool

	// writing is set while [mapSession.writeMap] runs, so
	// [mapSession.stop] interrupts only a write that may be stuck.
	writing atomic.Bool

	keepAlive       time.Duration
	keepAliveTicker *time.Ticker

	node *types.Node
	w    http.ResponseWriter

	log zerolog.Logger
}

func (h *Headscale) newMapSession(
	ctx context.Context,
	req tailcfg.MapRequest,
	w http.ResponseWriter,
	node *types.Node,
) *mapSession {
	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond) //nolint:gosec // weak random is fine for jitter

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		cancelCh: make(chan struct{}),

		keepAlive:       ka,
		keepAliveTicker: nil,

		log: log.With().
			Str(zf.Component, "poll").
			EmbedObject(node).
			Bool(zf.OmitPeers, req.OmitPeers).
			Bool(zf.Stream, req.Stream).
			Logger(),
	}
}

func (m *mapSession) isStreaming() bool {
	return m.req.Stream
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers
}

func (m *mapSession) resetKeepAlive() {
	m.keepAliveTicker.Reset(m.keepAlive)
}

// stop ends the session from outside its loop, e.g. on shutdown.
func (m *mapSession) stop() {
	if m.cancelChClosed.CompareAndSwap(false, true) {
		close(m.cancelCh)

		// A channel signal cannot interrupt a response write that is blocked on
		// HTTP/2 flow control, so a client that stopped reading would keep the
		// map session, and therefore server shutdown, alive indefinitely. An
		// expired write deadline resets the stream with INTERNAL_ERROR, which
		// the client reports as a server error, so it is only a bound: an idle
		// session sees cancelCh, and a write the client keeps reading finishes
		// first, both ending the stream cleanly. writeMap checks cancelChClosed
		// after raising writing, so one side always sees the other.
		if !m.writing.Load() {
			return
		}

		err := http.NewResponseController(m.w).SetWriteDeadline(time.Now().Add(stopWriteGrace))
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			m.log.Debug().Caller().Err(err).Msg("failed to interrupt map response write")
		}
	}
}

// afterServeLongPoll is called when a long-polling session ends and the node
// is disconnected.
func (m *mapSession) afterServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.Node.Ephemeral.InactivityTimeout)
	}
}

// serve handles non-streaming requests: the node tells us about its
// current configuration and only wants a status code back.
func (m *mapSession) serve() {
	err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		httpError(m.w, err)
		return
	}

	// A "lite" update (!Stream && OmitPeers) lets clients update their
	// endpoints without breaking an existing long poll. The client only
	// checks the status code.
	if m.isEndpointUpdate() {
		m.w.WriteHeader(http.StatusOK)
		mapResponseEndpointUpdates.WithLabelValues("ok").Inc()
	}
}

// serveLongPoll streams the node's map: a full map first, then whatever
// changes in what the node sees, as the world changes.
//
//nolint:gocyclo
func (m *mapSession) serveLongPoll() {
	m.log.Trace().Caller().Msg("long poll session started")

	// Add/Done must precede cleanup: LIFO defers make shutdown's Wait cover Disconnect.
	m.h.clientStreamsOpen.Add(1)
	defer m.h.clientStreamsOpen.Done()

	// connectGen is set by [state.State.Connect] below and captured by the
	// deferred cleanup. Each Connect acquires one live session in state;
	// the cleanup must release it with exactly one [state.State.Disconnect]
	// call in every exit path, or the node stays online forever.
	var (
		connectGen uint64
		sess       *mapper.Session
	)

	defer func() {
		m.stop()

		stillConnected := false
		if sess != nil {
			stillConnected = m.h.mapHub.Leave(sess)
		}

		if connectGen == 0 {
			return
		}

		// A node that drops its stream often reconnects within seconds
		// (mobile clients, network weather). Wait a little before marking
		// it offline so it does not flap; a reconnect's own Connect keeps
		// it online either way. A session replaced by another skips the
		// wait but still releases. A deleted or expired node cannot come
		// back through a map reconnect, so it skips the grace.
		node, nodeExists := m.h.state.GetNodeByID(m.node.ID)

		if !stillConnected && nodeExists && !node.IsExpired() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

		waitForReconnect:
			for range 10 {
				if m.h.mapHub.IsConnected(m.node.ID) {
					break
				}

				select {
				case <-m.h.mapBatcher.Done():
					// Reconnect grace has no purpose once the server is stopping.
					break waitForReconnect
				case <-ticker.C:
				}
			}
		}

		err := m.h.state.Disconnect(m.node.ID, connectGen)
		if err != nil {
			// A node deleted mid-session is gone by the time its own session
			// releases; that is the expected order, not a failure.
			if errors.Is(err, state.ErrNodeNotFound) {
				m.log.Debug().Caller().Err(err).Msg("node deleted before its session was released")
			} else {
				m.log.Error().Caller().Err(err).Msg("failed to disconnect node")
			}
		}

		m.afterServeLongPoll()
		m.log.Info().Caller().Msg("node has disconnected")
	}()

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	// The routes the node announces must be in the world before Connect
	// elects primaries, or a reconnecting router would briefly lose them.
	err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		m.log.Error().Caller().Err(err).Msg("failed to update node from initial MapRequest")
		// An explicit error, not a bare return: net/http would send an
		// empty 200, which the client reads as "unexpected EOF" and retries
		// forever (issue #3346).
		httpError(m.w, err)

		return
	}

	// Join before rendering the initial map, so a change committed between
	// the two wakes the loop instead of being lost.
	sess = m.h.mapHub.Join(m.node.ID, m.stop)
	if sess == nil {
		httpError(m.w, errServerShuttingDown)

		return
	}

	connectGen = m.h.state.Connect(m.node.ID)

	// Cancel ephemeral GC only after Connect succeeds, or a departed node
	// whose reconnect failed would have no deletion timer (issue #3382).
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Cancel(m.node.ID)
	}

	m.log.Info().Caller().Msg("node has connected")

	stream := mapper.NewStream(m.h.cfg, m.h.mapHub, m.node.ID, m.capVer)

	initial, err := stream.Initial(m.h.state.Snapshot())
	if err != nil {
		m.log.Error().Caller().Err(err).Msg("failed to render initial map")
		httpError(m.w, err)

		return
	}

	if !m.writeAll(initial) {
		return
	}

	// coalesce bounds how often an update is rendered, so a burst of
	// writes reaches the client as one update.
	coalesce := m.h.cfg.Tuning.BatchChangeDelay

	var lastUpdate time.Time

	for {
		select {
		case <-m.cancelCh:
			m.log.Trace().Caller().Msg("poll cancelled received")
			mapResponseEnded.WithLabelValues("cancelled").Inc()

			return

		case <-ctx.Done():
			m.log.Trace().Caller().Msg("poll context done")
			mapResponseEnded.WithLabelValues("done").Inc()

			return

		case <-sess.Wakes():
			if wait := coalesce - time.Since(lastUpdate); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return
				case <-m.cancelCh:
					return
				}
			}

			lastUpdate = time.Now()

			resps, err := stream.Update(m.h.state.Snapshot())
			if errors.Is(err, mapper.ErrNodeGone) {
				m.log.Info().Caller().Msg("node removed, ending map session")

				return
			}

			if err != nil {
				m.log.Error().Caller().Err(err).Msg("rendering map update")

				continue
			}

			if !m.writeAll(resps) {
				return
			}

		case pr := <-sess.Pings():
			if !m.writeAll([]*tailcfg.MapResponse{{PingRequest: pr}}) {
				return
			}

		case <-m.keepAliveTicker.C:
			err := m.writeMap(&keepAlive)
			if errors.Is(err, errMapSessionStopped) {
				mapResponseEnded.WithLabelValues("cancelled").Inc()

				return
			}

			if err != nil {
				m.log.Error().Caller().Err(err).Msg("cannot write keep alive")
				return
			}

			if debugHighCardinalityMetrics {
				mapResponseLastSentSeconds.WithLabelValues("keepalive", m.node.ID.String()).Set(float64(time.Now().Unix()))
			}

			mapResponseSent.WithLabelValues("ok", "keepalive").Inc()
			m.resetKeepAlive()
		}
	}
}

// writeAll writes resps in order and reports whether the stream is still
// usable.
func (m *mapSession) writeAll(resps []*tailcfg.MapResponse) bool {
	for _, resp := range resps {
		err := m.writeMap(resp)
		if errors.Is(err, errMapSessionStopped) {
			mapResponseEnded.WithLabelValues("cancelled").Inc()

			return false
		}

		if err != nil {
			m.log.Error().Caller().Err(err).Msg("cannot write update to client")
			mapResponseSent.WithLabelValues("error", "update").Inc()

			return false
		}

		mapResponseSent.WithLabelValues("ok", "update").Inc()
	}

	if len(resps) > 0 {
		m.resetKeepAlive()
	}

	return true
}

// writeMap writes the map response to the client.
// It handles compression if requested and any headers that need to be set.
// It also handles flushing the response if the [http.ResponseWriter]
// implements [http.Flusher].
func (m *mapSession) writeMap(msg *tailcfg.MapResponse) error {
	m.writing.Store(true)
	defer m.writing.Store(false)

	if m.cancelChClosed.Load() {
		return errMapSessionStopped
	}

	startWrite := time.Now()

	err := writeMapResponse(m.w, m.req.Compress, m.isStreaming(), msg)
	if err != nil {
		return err
	}

	m.log.Trace().
		Caller().
		TimeDiff("timeSpent", time.Now(), startWrite).
		Str(zf.MachineKey, m.node.MachineKey.String()).
		Bool("keepalive", msg.KeepAlive).
		Msg("finished writing mapresp to node")

	return nil
}

// writeMapResponse writes a single map response frame: the JSON body,
// zstd-framed when the client asked for compression, behind a little-endian
// length prefix. Tailscale clients request zstd unconditionally and decode
// every frame with it, so the compression step is not optional.
//
// It is shared with the deleted-node path in [noiseServer.PollNetMapHandler],
// which has no [mapSession] to write through.
func writeMapResponse(w http.ResponseWriter, compress string, flush bool, msg *tailcfg.MapResponse) error {
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling map response: %w", err)
	}

	if compress == util.ZstdCompression {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize, reservedResponseHeaderSize+len(jsonBody))
	//nolint:gosec // G115: JSON response size will not exceed uint32 max
	binary.LittleEndian.PutUint32(data, uint32(len(jsonBody)))
	data = append(data, jsonBody...)

	_, err = w.Write(data)
	if err != nil {
		return err
	}

	if flush {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		} else {
			log.Error().Caller().Msg("responseWriter does not implement http.Flusher, cannot flush")
		}
	}

	return nil
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}
