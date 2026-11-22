package mapper

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestInitialMapNotStarvedByReconnectStorm(t *testing.T) {
	const nodeCount = 300

	cfg, s, _ := dnsBenchTailnet(t, nodeCount, nil)
	_, err := s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`))
	require.NoError(t, err)

	h := NewHub()
	defer h.Close()

	h.Watch(s)
	nodes := s.ListNodes()
	before := s.Snapshot().Rev()
	latencies := make([]time.Duration, nodeCount)
	start := make(chan struct{})
	renderStarted, writerCommitted := make(chan struct{}), make(chan struct{})

	var (
		started                           sync.Once
		activeRenders, writesDuringRender atomic.Int32
	)

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)

		<-renderStarted

		node := nodes.At(0)
		for i := range nodeCount * 2 {
			err := s.UpdateNodeFromMapRequest(node.ID(), tailcfg.MapRequest{NodeKey: node.NodeKey(), Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1))}})
			if !assert.NoError(t, err) {
				if i == 0 {
					close(writerCommitted)
				}

				return
			}

			if activeRenders.Load() > 0 {
				writesDuringRender.Add(1)
			}

			if i == 0 {
				close(writerCommitted)
			}
		}
	}()

	var wg sync.WaitGroup
	for i, node := range nodes.All() {
		wg.Go(func() {
			<-start

			begin := time.Now()
			stop := make(chan struct{})

			sess := h.Join(node.ID(), func() { close(stop) })

			if !assert.NotNil(t, sess) {
				return
			}

			generation := s.Connect(node.ID())
			if !assert.NotZero(t, generation) {
				h.Leave(sess)
				return
			}
			defer func() {
				h.Leave(sess)

				err := s.Disconnect(node.ID(), generation)
				if err != nil {
					t.Errorf("disconnecting reconnect session: %v", err)
				}
			}()

			err := s.UpdateNodeFromMapRequest(node.ID(), tailcfg.MapRequest{NodeKey: node.NodeKey(), Hostinfo: &tailcfg.Hostinfo{Hostname: fmt.Sprintf("reconnect-%d", node.ID()), OS: "linux"}})
			if err != nil {
				t.Errorf("updating reconnect report: %v", err)
				return
			}

			release, ok := h.RenderFirst(t.Context().Done(), stop)
			if !assert.True(t, ok) {
				return
			}
			defer release()

			activeRenders.Add(1)
			defer activeRenders.Add(-1)

			started.Do(func() { close(renderStarted) })
			<-writerCommitted // At least one state write overlaps pending first maps.

			st := NewStream(cfg, h, node.ID(), capVer)
			st.Attach(sess)

			out, err := st.Initial(s.Snapshot())
			if err != nil {
				t.Errorf("rendering reconnect initial: %v", err)
				return
			}

			if assert.NotEmpty(t, out) {
				assert.NotNil(t, out[0].Node)
				assert.Equal(t, node.ID().NodeID(), out[0].Node.ID)
			}

			st.Delivered()

			latencies[i] = time.Since(begin)
		})
	}

	close(start)
	wg.Wait()
	<-writerDone
	require.Greater(t, s.Snapshot().Rev(), before)
	require.Positive(t, writesDuringRender.Load(), "state writers must overlap the initial-map workload")
	slices.Sort(latencies)
	t.Logf("initial maps for %d nodes, workers=%d, overlapping writes=%d: p50=%s p95=%s max=%s", nodeCount, runtime.GOMAXPROCS(0), writesDuringRender.Load(), latencies[nodeCount/2], latencies[nodeCount*95/100], latencies[nodeCount-1])
	require.Positive(t, latencies[0], "every requested first map must complete")
	require.Less(t, latencies[nodeCount-1], 30*time.Second)
}
