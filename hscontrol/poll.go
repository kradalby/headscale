package hscontrol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
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

	// writeStallTimeout is how long one write may block before the session
	// is taken as stalled: it leaves the hub and stops, so a client that
	// stopped reading cannot hold a session that receives nothing. The
	// clock starts once the frame is encoded and progress counts per written
	// chunk ([frameChunkSize]), so a reader slower than one chunk per
	// timeout, about 3 KB/s once the transport's buffers are full, is
	// taken as stalled too.
	writeStallTimeout = 5 * time.Second
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
	stopOnce       sync.Once

	// writing is the number of the encoded write [mapSession.writeMap] is
	// sending, 0 while encoding or idle: [mapSession.stop] interrupts only
	// a write that may be stuck, and a stall timer only the write it was set for.
	writing atomic.Uint64

	// hubSession is the session's place in the map hub, left on a stall.
	hubSession atomic.Pointer[mapper.Session]

	// writeSeq numbers writes. stallTimeout is [writeStallTimeout],
	// shorter in tests.
	writeSeq     atomic.Uint64
	stallTimeout time.Duration

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
		stallTimeout:    writeStallTimeout,

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

// stallWrite ends the session if write seq is still the one running: a
// timer firing as its write returns finds no write, or the next one under
// another number.
func (m *mapSession) stallWrite(seq uint64) {
	if m.writing.Load() != seq {
		return
	}

	m.stall()
}

// stall ends a session whose write has blocked past [writeStallTimeout]:
// it leaves the hub at once, so the node no longer counts as connected,
// and stops, which bounds the write by [stopWriteGrace].
func (m *mapSession) stall() {
	m.log.Warn().Caller().Dur("stall", m.stallTimeout).Msg("map write stalled, ending session")

	if sess := m.hubSession.Load(); sess != nil {
		m.h.mapHub.Leave(sess)
	}

	m.stop()
}

// stop ends the session from outside its loop, e.g. on shutdown.
func (m *mapSession) stop() {
	// Handler cleanup must wait for a concurrent deadline call before its
	// ResponseWriter is released by net/http.
	m.stopOnce.Do(func() {
		m.cancelChClosed.Store(true)
		close(m.cancelCh)

		// A channel signal cannot interrupt a response write that is blocked on
		// HTTP/2 flow control, so a client that stopped reading would keep the
		// map session, and therefore server shutdown, alive indefinitely. An
		// expired write deadline resets the stream with INTERNAL_ERROR, which
		// the client reports as a server error, so it is only a bound: an idle
		// session sees cancelCh, and a write the client keeps reading finishes
		// first, both ending the stream cleanly. writeMap checks cancelChClosed
		// after setting writing, so one side always sees the other.
		if m.writing.Load() == 0 {
			return
		}

		err := http.NewResponseController(m.w).SetWriteDeadline(time.Now().Add(stopWriteGrace))
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			m.log.Debug().Caller().Err(err).Msg("failed to interrupt map response write")
		}
	})
}

// renderFirst renders stream's initial map within the hub's bound on
// concurrent first maps, releasing its slot even if the render panics. It
// reports false when done closed before a slot was free.
func (m *mapSession) renderFirst(done <-chan struct{}, stream *mapper.Stream) ([]*tailcfg.MapResponse, bool, error) {
	release, ok := m.h.mapHub.RenderFirst(done, m.cancelCh)
	if !ok {
		return nil, false, nil
	}
	defer release()

	initial, err := stream.Initial(m.h.state.Snapshot())

	return initial, true, err
}

// afterServeLongPoll is called when a long-polling session ends and the node
// is disconnected.
func (m *mapSession) afterServeLongPoll() {
	// The live node, not the session's copy: it may have been deleted, or
	// re-registered permanent, while the session ran.
	if node, ok := m.h.state.GetNodeByID(m.node.ID); ok && node.IsEphemeral() {
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.Node.Ephemeral.InactivityTimeout)
	}
}

// serve handles non-streaming requests: the node tells us about its
// current configuration and only wants a status code back.
func (m *mapSession) serve() {
	err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
	if err != nil {
		// Tailscale maps a streaming 404 to re-registration; this lite
		// endpoint only gets its status logged, and the client's next full
		// request carries the new key anyway. The status is still kept
		// truthful: a request authenticated with a replaced key, or one
		// whose node was deleted, is a 404, not a 500.
		if errors.Is(err, state.ErrNodeKeyChanged) || errors.Is(err, state.ErrNodeNotInNodeStore) {
			err = NewHTTPError(http.StatusNotFound, "node not found", err)
		}

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
				case <-m.h.mapHub.Done():
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

	// Streaming requests are read-only since capability 68: their captured
	// payload may predate an explicit update or reauthentication.
	// Join before rendering the initial map, so a change committed between
	// the two wakes the loop instead of being lost.
	sess = m.h.mapHub.Join(m.node.ID, m.stop)
	m.hubSession.Store(sess)

	if sess == nil {
		httpError(m.w, errServerShuttingDown)

		return
	}

	connectGen = m.h.state.Connect(m.node.ID)
	if connectGen == 0 {
		// An empty 200 would make the client retry an unexpected EOF (#3346).
		httpError(m.w, state.ErrNodeNotFound)

		return
	}

	// Cancel ephemeral GC only after Connect succeeds, or a departed node
	// whose reconnect failed would have no deletion timer (issue #3382).
	// Cancelling a node without a timer does nothing.
	m.h.ephemeralGC.Cancel(m.node.ID)

	m.log.Info().Caller().Msg("node has connected")

	stream := mapper.NewStream(m.h.cfg, m.h.mapHub, m.node.ID, m.capVer)
	stream.Attach(sess)

	initial, ok, err := m.renderFirst(ctx.Done(), stream)
	if !ok {
		return
	}

	if err != nil {
		m.log.Error().Caller().Err(err).Msg("failed to render initial map")
		httpError(m.w, err)

		return
	}

	if !m.writeAll(initial) {
		return
	}

	stream.Delivered()

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

			stream.Delivered()

		case pr := <-sess.Pings():
			if !m.writeAll(stream.Ping(pr)) {
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
	seq := m.writeSeq.Add(1)

	defer m.writing.Store(0)

	if m.cancelChClosed.Load() {
		return errMapSessionStopped
	}

	startWrite := time.Now()

	// A slow reader keeps the write moving; one that stops reading for the
	// budget is taken as gone. Armed by the first progress, once the frame
	// is encoded: encoding is the server's time, not the client's.
	stalled := time.AfterFunc(m.stallTimeout, func() { m.stallWrite(seq) })
	stalled.Stop()

	defer stalled.Stop()

	progress := func() { stalled.Reset(m.stallTimeout) }

	// Sessions sending the same update share its encoding.
	encode := func(msg *tailcfg.MapResponse, compress bool) ([]byte, error) {
		body, err := m.h.mapHub.Encode(msg, compress, encodeMapResponse)
		if err != nil {
			return nil, err
		}

		// Encoding may outlast the stop grace. A stopped session sends no
		// frame; only a write already sending needs a deadline to interrupt it.
		m.writing.Store(seq)

		if m.cancelChClosed.Load() {
			return nil, errMapSessionStopped
		}

		return body, nil
	}

	err := writeMapFrame(m.w, m.isStreaming(), msg, m.req.Compress == util.ZstdCompression, encode, progress)
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
	return writeMapFrame(w, flush, msg, compress == util.ZstdCompression, encodeMapResponse, nil)
}

// encodeMapResponse marshals msg and, when compress, zstd compresses it.
func encodeMapResponse(msg *tailcfg.MapResponse, compress bool) ([]byte, error) {
	if msg == &keepAlive {
		return keepAliveFrame(compress)
	}

	jsonBody, err := mapper.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshalling map response: %w", err)
	}

	if compress {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	return jsonBody, nil
}

// writeMapFrame writes msg encoded by encode, length prefixed.
// When streaming it writes in chunks, calling progress once the frame is
// encoded and after each chunk the client accepted, so a caller can tell a
// slow reader from a stopped one.
func writeMapFrame(
	w http.ResponseWriter,
	flush bool,
	msg *tailcfg.MapResponse,
	compress bool,
	encode func(*tailcfg.MapResponse, bool) ([]byte, error),
	progress func(),
) error {
	jsonBody, err := encode(msg, compress)
	if err != nil {
		return err
	}

	data := make([]byte, reservedResponseHeaderSize, reservedResponseHeaderSize+len(jsonBody))
	//nolint:gosec // G115: JSON response size will not exceed uint32 max
	binary.LittleEndian.PutUint32(data, uint32(len(jsonBody)))
	data = append(data, jsonBody...)

	if progress != nil {
		progress()
	}

	if !flush {
		_, err = w.Write(data)

		return err
	}

	for chunk := range slices.Chunk(data, frameChunkSize) {
		_, err = w.Write(chunk)
		if err != nil {
			return err
		}

		// HTTP/2 buffers a small write, so only the flush can fail.
		err = flushError(w)
		if errors.Is(err, http.ErrNotSupported) {
			log.Error().Caller().Msg("responseWriter does not implement http.Flusher, cannot flush")
		} else if err != nil {
			return err
		}

		if progress != nil {
			progress()
		}
	}

	return nil
}

// flushError flushes w and returns the error of the writer it wraps: the
// middleware wrapping the poll's writer implements only Flush, which drops
// it, and [http.ResponseController] would stop there.
func flushError(w http.ResponseWriter) error {
	for inner := w; ; {
		if f, ok := inner.(interface{ FlushError() error }); ok {
			return f.FlushError()
		}

		u, ok := inner.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}

		inner = u.Unwrap()
	}

	return http.NewResponseController(w).Flush()
}

// frameChunkSize is how much of a frame is written before checking the
// client keeps reading.
const frameChunkSize = 16 << 10

// keepAliveFrame returns keepAlive encoded, which every session sends.
func keepAliveFrame(compress bool) ([]byte, error) {
	i := 0
	if compress {
		i = 1
	}

	f := &keepAliveFrames[i]
	f.once.Do(func() {
		f.b, f.err = json.Marshal(&keepAlive)
		if f.err == nil && compress {
			f.b = zstdframe.AppendEncode(nil, f.b, zstdframe.FastestCompression)
		}
	})

	return f.b, f.err
}

var keepAliveFrames [2]struct {
	once sync.Once
	b    []byte
	err  error
}

var keepAlive = tailcfg.MapResponse{
	KeepAlive: true,
}
