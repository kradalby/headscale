package mapper

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestHubConcurrentSessionOperations(t *testing.T) {
	for _, count := range []int{5, 1000} {
		t.Run(fmt.Sprintf("nodes=%d", count), func(t *testing.T) {
			h := NewHub()
			defer h.Close()

			var wg sync.WaitGroup

			for n := range count {
				id := types.NodeID(n + 1)

				wg.Go(func() {
					sess := h.Join(id, func() {})
					require.NotNil(t, sess)
					require.True(t, h.IsConnected(id))
					require.Equal(t, 1, h.Connected()[id])
					require.True(t, h.Ping(id, &tailcfg.PingRequest{URL: "https://example.test/ping"}))
					require.NotNil(t, <-sess.Pings())
					require.False(t, h.Leave(sess))
					require.False(t, h.IsConnected(id))
				})
			}

			wg.Wait()
			require.Empty(t, h.Connected())
		})
	}
}

func TestHubConcurrentCloseIsIdempotent(t *testing.T) {
	h := NewHub()

	const sessions = 10

	var stopped atomic.Int32

	for n := range sessions {
		done := make(chan struct{})

		h.Join(types.NodeID(n+1), func() { close(done); stopped.Add(1) })
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(h.Close)
	}

	wg.Wait()
	require.EqualValues(t, sessions, stopped.Load(), "each stop callback runs exactly once")

	select {
	case <-h.Done():
	default:
		t.Fatal("closed hub did not signal shutdown")
	}

	require.Nil(t, h.Join(100, func() { t.Error("refused session was stopped") }))
}

func TestHubStopCallbacksDoNotHoldLock(t *testing.T) {
	for _, action := range []string{"evict", "close", "delete"} {
		t.Run(action, func(t *testing.T) {
			h := NewHub()
			callback := make(chan struct{})

			h.Join(1, func() { _ = h.Connected(); close(callback) })

			done := make(chan struct{})

			go func() {
				switch action {
				case "evict":
					for range maxConcurrentMapSessionsPerNode {
						h.Join(1, func() {})
					}
				case "close":
					h.Close()
				case "delete":
					h.forget(1)
				}

				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("stop callback deadlocked with hub lock")
			}

			select {
			case <-callback:
			default:
				t.Fatal("session not stopped")
			}
		})
	}
}

func TestHubWakeAndPingRemainIndependentDuringChurn(t *testing.T) {
	h := NewHub()
	defer h.Close()

	const nodes = 1000

	sessions := make([]*Session, nodes)
	for i := range sessions {
		sessions[i] = h.Join(types.NodeID(i+1), func() {})
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			h.wake(true, nil)
		}
	})
	wg.Go(func() {
		for _, sess := range sessions {
			require.True(t, h.Ping(sess.NodeID, &tailcfg.PingRequest{}))
		}
	})
	wg.Go(func() {
		for i := range 500 {
			id := types.NodeID(i + 1)
			s := h.Join(id, func() {})
			h.Leave(s)
		}
	})
	wg.Wait()

	for _, sess := range sessions {
		require.Len(t, sess.wakes, 1, "full-update wake coalesces without dropping readiness")
		require.Len(t, sess.pings, 1, "full update cannot absorb independent ping requests")
		require.True(t, h.IsConnected(sess.NodeID))
	}
}

func TestHubCleanupCannotOrphanReconnectedSession(t *testing.T) {
	h := NewHub()
	defer h.Close()

	now := time.Now()
	h.now = func() time.Time { return now }
	old := h.Join(1, func() {})
	h.setLastPeers(old, 1, sentView{ids: []types.NodeID{2}, rev: 1})
	h.Leave(old)

	now = now.Add(peerHistoryTTL + time.Second)

	var (
		sess *Session
		wg   sync.WaitGroup
	)
	wg.Go(func() { sess = h.Join(1, func() {}) })
	wg.Go(h.expireHistory)
	wg.Wait()
	require.NotNil(t, sess)
	require.True(t, h.IsConnected(1))
	require.Equal(t, 1, h.Connected()[1])
	require.False(t, h.Leave(sess))
}

func TestAcceptedPingsKeepRecipientsCountsAndFIFO(t *testing.T) {
	const nodes, perNode = 4, 6

	h := NewHub()
	defer h.Close()

	sessions := make(map[types.NodeID][]*Session, nodes)
	for n := range nodes {
		id := types.NodeID(n + 1)
		for range 2 {
			sessions[id] = append(sessions[id], h.Join(id, func() {}))
		}
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			h.wake(true, nil)
		}
	})
	wg.Go(func() {
		for i := range 1000 {
			id := types.NodeID(i%nodes + 1)
			s := h.Join(id, func() {})
			h.Leave(s)
		}
	})

	for n := range nodes {
		id := types.NodeID(n + 1)

		wg.Go(func() {
			for i := range perNode {
				pr := &tailcfg.PingRequest{URL: fmt.Sprintf("https://ping.test/node/%d/sequence/%d", id, i)}
				require.True(t, h.Ping(id, pr), "below-capacity ping must be accepted")
			}
		})
	}

	wg.Wait()

	for id, streams := range sessions {
		for _, sess := range streams {
			require.False(t, sess.left, "churn cannot evict stable streams below the cap")
			require.Len(t, sess.pings, perNode)

			stream := NewStream(&types.Config{}, h, id, capVer)

			for i := range perNode {
				pr := <-sess.Pings()
				require.Equal(t, fmt.Sprintf("https://ping.test/node/%d/sequence/%d", id, i), pr.URL, "recipient and FIFO must be exact")
				out := stream.Ping(pr)
				require.Len(t, out, 1)
				require.Same(t, pr, out[0].PingRequest)
				require.Nil(t, out[0].Node)
				require.Nil(t, out[0].PacketFilters)
				require.Nil(t, out[0].SSHPolicy)
				require.Empty(t, out[0].Peers)
			}

			require.Empty(t, sess.pings, "accepted pings must not duplicate")
		}
	}
}

func TestPingTrueMeansAtLeastOneSessionAccepted(t *testing.T) {
	h := NewHub()
	defer h.Close()

	first, full := h.Join(1, func() {}), h.Join(1, func() {})
	for i := range cap(first.pings) {
		require.True(t, h.Ping(1, &tailcfg.PingRequest{URL: strconv.Itoa(i)}))
	}

	require.False(t, h.Ping(1, &tailcfg.PingRequest{URL: "rejected"}))
	require.Equal(t, "0", (<-first.Pings()).URL)
	last := &tailcfg.PingRequest{URL: "accepted-by-first-only"}
	require.True(t, h.Ping(1, last))

	for i := 1; i < cap(first.pings); i++ {
		require.Equal(t, strconv.Itoa(i), (<-first.Pings()).URL)
	}

	require.Same(t, last, <-first.Pings())

	for i := range cap(full.pings) {
		require.Equal(t, strconv.Itoa(i), (<-full.Pings()).URL)
	}

	require.Empty(t, first.pings)
	require.Empty(t, full.pings)
}

func TestHubConcurrentCloseAndForgetStopsOnce(t *testing.T) {
	for range 100 {
		h := NewHub()
		stopped := make(chan struct{})

		var count atomic.Int32

		h.Join(1, func() { count.Add(1); close(stopped) })

		start := make(chan struct{})

		var wg sync.WaitGroup
		wg.Go(func() { <-start; h.Close() })
		wg.Go(func() { <-start; h.forget(1) })
		close(start)
		wg.Wait()
		require.EqualValues(t, 1, count.Load())
		require.Empty(t, h.Connected())

		select {
		case <-stopped:
		default:
			t.Fatal("teardown failed to stop session")
		}
	}
}

func TestHubClosedRefusesLateDelivery(t *testing.T) {
	h := NewHub()
	sess := h.Join(1, func() {})
	h.Close()
	require.False(t, h.IsConnected(1))
	require.False(t, h.Ping(1, &tailcfg.PingRequest{}))
	h.wake(true, nil)
	require.Empty(t, sess.pings)
	require.Empty(t, sess.wakes)
	require.Nil(t, h.Join(1, func() { t.Error("closed Hub admitted a late session") }))
	require.False(t, h.Leave(sess))
	h.setLastPeers(sess, 1, sentView{ids: []types.NodeID{2}, rev: 1})
	require.Empty(t, h.lastPeers(1), "a closed session cannot recreate delivery history")
}
