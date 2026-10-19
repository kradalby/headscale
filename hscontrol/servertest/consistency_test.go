package servertest_test

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestConsistency verifies that all nodes converge to the same
// view of the network and that no updates are lost during various
// operations.
func TestConsistency(t *testing.T) {
	t.Parallel()

	t.Run("all_nodes_converge", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 5)
		servertest.AssertMeshComplete(t, h.Clients())
		servertest.AssertConsistentState(t, h.Clients())
		servertest.AssertSymmetricVisibility(t, h.Clients())
	})

	t.Run("self_node_has_correct_hostname", func(t *testing.T) {
		t.Parallel()

		h := servertest.NewHarness(t, 3)
		for _, c := range h.Clients() {
			assert.Equal(t, c.Name, c.SelfName(),
				"client %s self name should match", c.Name)
		}
	})

	t.Run("update_count_positive", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)
		// After mesh formation, each client should have received
		// at least one update.
		for _, c := range h.Clients() {
			assert.Positive(t, c.UpdateCount(),
				"client %s should have received at least one update", c.Name)
		}
	})

	t.Run("new_node_visible_to_all", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		newClient := h.AddClient(t)
		h.WaitForMeshComplete(t, 10*time.Second)

		// Verify every original client sees the new node.
		for _, c := range h.Clients() {
			if c == newClient {
				continue
			}

			_, found := c.PeerByName(newClient.Name)
			assert.True(t, found,
				"client %s should see new client %s", c.Name, newClient.Name)
		}

		// And the new node sees all others.
		for _, c := range h.Clients() {
			if c == newClient {
				continue
			}

			_, found := newClient.PeerByName(c.Name)
			assert.True(t, found,
				"new client %s should see %s", newClient.Name, c.Name)
		}
	})

	t.Run("interleaved_join_and_leave", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 5)

		// Disconnect 2 nodes.
		h.Client(0).Disconnect(t)
		h.Client(1).Disconnect(t)

		// Add 3 new nodes while 2 are disconnected.
		c5 := h.AddClient(t)
		c6 := h.AddClient(t)
		c7 := h.AddClient(t)

		// Wait for new nodes to see at least all other connected
		// clients (they may also see the disconnected nodes during
		// the grace period, so we check >= not ==).
		connected := h.ConnectedClients()
		minPeers := len(connected) - 1

		for _, c := range connected {
			c.WaitForPeers(t, minPeers, 30*time.Second)
		}

		// Verify the new nodes can see each other.
		for _, a := range []*servertest.TestClient{c5, c6, c7} {
			for _, b := range []*servertest.TestClient{c5, c6, c7} {
				if a == b {
					continue
				}

				_, found := a.PeerByName(b.Name)
				assert.True(t, found,
					"new client %s should see %s", a.Name, b.Name)
			}
		}

		// Verify all connected clients see each other (consistent state).
		servertest.AssertConsistentState(t, connected)
	})
}

// peerNameReference retains the d00f135bf client state needed by the exact
// pre-index methods below; this file is in the external test package.
type peerNameReference struct {
	Name    string
	mu      sync.RWMutex
	netmap  *netmap.NetworkMap
	history []*netmap.NetworkMap
	updates chan *netmap.NetworkMap
}

// PeerByName is copied from client.go at d00f135bf; only the receiver type differs.
func (c *peerNameReference) PeerByName(hostname string) (tailcfg.NodeView, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.netmap == nil {
		return tailcfg.NodeView{}, false
	}

	for _, p := range c.netmap.Peers {
		hi := p.Hostinfo()
		if hi.Valid() && hi.Hostname() == hostname {
			return p, true
		}
	}

	return tailcfg.NodeView{}, false
}

// UpdateFullNetmap retains the old update cost for paired benchmarks.
func (c *peerNameReference) UpdateFullNetmap(nm *netmap.NetworkMap) {
	c.mu.Lock()
	c.netmap = nm
	c.history = append(c.history, nm)
	c.mu.Unlock()

	// Non-blocking send to the updates channel.
	select {
	case c.updates <- nm:
	default:
	}
}

// assertSymmetricVisibilityReference retains the complete d00f135bf loop.
func assertSymmetricVisibilityReference(tb testing.TB, clients []*peerNameReference) {
	tb.Helper()

	for _, a := range clients {
		for _, b := range clients {
			if a == b {
				continue
			}

			_, aSeesB := a.PeerByName(b.Name)

			_, bSeesA := b.PeerByName(a.Name)
			if aSeesB != bSeesA {
				tb.Errorf("AssertSymmetricVisibility: %s sees %s = %v, but %s sees %s = %v",
					a.Name, b.Name, aSeesB, b.Name, a.Name, bSeesA)
			}
		}
	}
}

func peerNameNode(id int, name string) tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:       tailcfg.NodeID(id),
		Hostinfo: (&tailcfg.Hostinfo{Hostname: name}).View(),
	}).View()
}

type peerNameAssertionRecorder struct {
	testing.TB

	errors     []string
	afterError func(int)
}

func (r *peerNameAssertionRecorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
	if r.afterError != nil {
		r.afterError(len(r.errors))
	}
}

func TestAssertSymmetricVisibilityDifferential(t *testing.T) {
	t.Parallel()

	for _, topology := range []string{"empty", "sparse", "dense", "asymmetric"} {
		t.Run(topology, func(t *testing.T) {
			t.Parallel()

			clients, references := peerNameMesh(64, topology)
			got := &peerNameAssertionRecorder{TB: t}
			want := &peerNameAssertionRecorder{TB: t}

			for range 2 {
				servertest.AssertSymmetricVisibility(got, clients)
				assertSymmetricVisibilityReference(want, references)
			}

			assert.Equal(t, want.errors, got.errors)

			if topology == "asymmetric" {
				assert.NotEmpty(t, got.errors)
			} else {
				assert.Empty(t, got.errors)
			}
		})
	}
}

func peerNameMesh(size int, topology string) ([]*servertest.TestClient, []*peerNameReference) {
	clients := make([]*servertest.TestClient, size)
	references := make([]*peerNameReference, size)

	nodes := make([]tailcfg.NodeView, size)
	for i := range nodes {
		nodes[i] = peerNameNode(i+1, fmt.Sprintf("peer-%d", i))
	}

	for i := range clients {
		nm := &netmap.NetworkMap{}

		for j, node := range nodes {
			if i == j || topology == "empty" ||
				(topology == "sparse" && i/2 != j/2) ||
				(topology == "asymmetric" && i == 0 && j == 1) {
				continue
			}

			nm.Peers = append(nm.Peers, node)
		}

		name := nodes[i].Hostinfo().Hostname()
		clients[i] = &servertest.TestClient{Name: name}
		clients[i].UpdateFullNetmap(nm)
		references[i] = &peerNameReference{Name: name}
		references[i].UpdateFullNetmap(nm)
	}

	return clients, references
}

func TestAssertSymmetricVisibilityGenerations(t *testing.T) {
	t.Parallel()

	clients, references := peerNameMesh(3, "empty")
	publish := func(i int, names ...string) {
		nm := &netmap.NetworkMap{}
		for j, name := range names {
			nm.Peers = append(nm.Peers, peerNameNode(j+1, name))
		}

		clients[i].UpdateFullNetmap(nm)
		references[i].UpdateFullNetmap(nm)
	}

	var errors [2][]string

	for run := range 2 {
		publish(0, "peer-1")
		publish(1)
		publish(2)

		recorder := &peerNameAssertionRecorder{TB: t, afterError: func(n int) {
			switch n {
			case 1:
				publish(0, "peer-2")
				publish(1, "peer-0")
			case 2:
				publish(2, "peer-0")
				clients[1].UpdateFullNetmap(nil)
				references[1].UpdateFullNetmap(nil)
			}
		}}
		if run == 0 {
			assertSymmetricVisibilityReference(recorder, references)
		} else {
			servertest.AssertSymmetricVisibility(recorder, clients)
		}

		errors[run] = recorder.errors
	}

	assert.Len(t, errors[0], 2)
	assert.Equal(t, errors[0], errors[1])
}

func TestAssertSymmetricVisibilityInvocationLifetime(t *testing.T) {
	t.Parallel()

	clients, references := peerNameMesh(64, "dense")
	servertest.AssertSymmetricVisibility(t, clients)
	assertSymmetricVisibilityReference(t, references)
	// The same pointer can have different contents between assertion invocations.
	clients[0].Netmap().Peers[0] = peerNameNode(3, "replacement")
	got := &peerNameAssertionRecorder{TB: t}
	want := &peerNameAssertionRecorder{TB: t}

	servertest.AssertSymmetricVisibility(got, clients)
	assertSymmetricVisibilityReference(want, references)
	assert.Len(t, want.errors, 2)
	assert.Equal(t, want.errors, got.errors)
}

func TestAssertSymmetricVisibilityInvalidPeers(t *testing.T) {
	t.Parallel()

	padding := make([]tailcfg.NodeView, 16)
	for i := range padding {
		padding[i] = peerNameNode(100+i, fmt.Sprintf("outside-%d", i))
	}

	for _, tc := range []struct {
		name       string
		size       int
		peers      []tailcfg.NodeView
		wantPanic  bool
		wantErrors int
	}{
		{"indexed_invalid_view_first", 64, append([]tailcfg.NodeView{{}}, padding...), true, 0},
		{"indexed_error_before_invalid_view", 64, append([]tailcfg.NodeView{peerNameNode(1, "peer-1"), {}}, padding...), true, 1},
		{"invalid_hostinfo", 2, []tailcfg.NodeView{(&tailcfg.Node{}).View()}, false, 0},
		{"match_before_invalid_view", 2, []tailcfg.NodeView{
			peerNameNode(1, "peer-1"), {},
		}, false, 2},
		{"invalid_view_first", 2, []tailcfg.NodeView{{}}, true, 0},
		{"error_before_invalid_view", 3, []tailcfg.NodeView{
			peerNameNode(1, "peer-1"), {},
		}, true, 1},
		{"empty_and_duplicate_names", 2, []tailcfg.NodeView{
			peerNameNode(1, ""), peerNameNode(2, ""),
		}, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clients, references := peerNameMesh(tc.size, "empty")
			nm := &netmap.NetworkMap{Peers: tc.peers}
			clients[0].UpdateFullNetmap(nm)
			references[0].UpdateFullNetmap(nm)

			if tc.name == "empty_and_duplicate_names" {
				clients[1].Name = ""
				references[1].Name = ""
			}

			got := &peerNameAssertionRecorder{TB: t}
			want := &peerNameAssertionRecorder{TB: t}

			var panics [2]string

			for run := range 2 {
				func() {
					defer func() {
						if p := recover(); p != nil {
							panics[run] = fmt.Sprint(p)
						}
					}()

					if run == 0 {
						assertSymmetricVisibilityReference(want, references)
					} else {
						servertest.AssertSymmetricVisibility(got, clients)
					}
				}()
			}

			assert.Equal(t, tc.wantPanic, panics[0] != "")
			assert.Len(t, want.errors, tc.wantErrors)
			assert.Equal(t, panics[0], panics[1])
			assert.Equal(t, want.errors, got.errors)
		})
	}
}

func TestAssertSymmetricVisibilityConcurrentUpdates(t *testing.T) {
	t.Parallel()

	clients, _ := peerNameMesh(16, "dense")

	maps := make([]*netmap.NetworkMap, len(clients))
	for i, c := range clients {
		maps[i] = c.Netmap()
	}

	start := make(chan struct{})

	var workers sync.WaitGroup
	for _, client := range clients {
		workers.Go(func() {
			<-start

			for i := range 128 {
				client.UpdateFullNetmap(maps[i%len(maps)])
				client.UpdateFullNetmap(nil)
			}
		})
	}

	for range 2 {
		workers.Go(func() {
			<-start

			for range 32 {
				recorder := &peerNameAssertionRecorder{TB: t}
				servertest.AssertSymmetricVisibility(recorder, clients)
			}
		})
	}

	close(start)
	workers.Wait()

	for i, c := range clients {
		c.UpdateFullNetmap(maps[i])
	}

	servertest.AssertSymmetricVisibility(t, clients)
}

// Each invocation includes building and discarding the local indexes. These
// measure the test harness only, not production server throughput.
func BenchmarkAssertSymmetricVisibility(b *testing.B) {
	for _, size := range []int{0, 1, 8, 64, 256, 512} {
		for _, topology := range []string{"empty", "sparse", "dense"} {
			for _, implementation := range []string{"reference", "indexed"} {
				b.Run(fmt.Sprintf("clients=%d/%s/%s", size, topology, implementation), func(b *testing.B) {
					clients, references := peerNameMesh(size, topology)

					b.ReportAllocs()
					b.ResetTimer()

					for range b.N {
						if implementation == "reference" {
							assertSymmetricVisibilityReference(b, references)
						} else {
							servertest.AssertSymmetricVisibility(b, clients)
						}
					}
				})
			}
		}
	}
}

func BenchmarkAssertSymmetricVisibilityRetained(b *testing.B) {
	for _, size := range []int{8, 64, 256} {
		for _, implementation := range []string{"reference", "indexed"} {
			b.Run(fmt.Sprintf("clients=%d/%s", size, implementation), func(b *testing.B) {
				clients, references := peerNameMesh(size, "dense")

				runtime.GC()

				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				b.ReportAllocs()
				b.ResetTimer()

				for range b.N {
					if implementation == "reference" {
						assertSymmetricVisibilityReference(b, references)
					} else {
						servertest.AssertSymmetricVisibility(b, clients)
					}
				}

				b.StopTimer()
				runtime.GC()
				runtime.ReadMemStats(&after)
				retained := float64(after.HeapAlloc) - float64(before.HeapAlloc)
				b.ReportMetric(retained, "retained-B")
				runtime.KeepAlive(clients)
				runtime.KeepAlive(references)
			})
		}
	}
}

// A small assertion over much larger netmaps exposes cold early-hit and miss costs.
func BenchmarkAssertSymmetricVisibilityPositions(b *testing.B) {
	for _, size := range []int{0, 1, 8, 64, 512, 2048} {
		for _, position := range []string{"early", "late", "miss"} {
			for _, implementation := range []string{"reference", "indexed"} {
				b.Run(fmt.Sprintf("peers=%d/%s/%s", size, position, implementation), func(b *testing.B) {
					clients, references := peerNameMesh(2, "empty")
					for i := range clients {
						nm := &netmap.NetworkMap{Peers: make([]tailcfg.NodeView, size)}
						for j := range nm.Peers {
							nm.Peers[j] = peerNameNode(j+1, fmt.Sprintf("other-%d", j))
						}

						if size > 0 && position != "miss" {
							index := 0
							if position == "late" {
								index = size - 1
							}

							nm.Peers[index] = peerNameNode(index+1, clients[1-i].Name)
						}

						clients[i].UpdateFullNetmap(nm)
						references[i].UpdateFullNetmap(nm)
					}

					b.ReportAllocs()
					b.ResetTimer()

					for range b.N {
						if implementation == "reference" {
							assertSymmetricVisibilityReference(b, references)
						} else {
							servertest.AssertSymmetricVisibility(b, clients)
						}
					}
				})
			}
		}
	}
}

func TestAssertSymmetricVisibilitySamePointerPublication(t *testing.T) {
	t.Parallel()

	clients, references := peerNameMesh(64, "empty")

	maps := make([]*netmap.NetworkMap, len(clients))
	for i := range maps {
		maps[i] = &netmap.NetworkMap{}
	}

	publish := func(i int, names ...string) {
		maps[i].Peers = nil
		for j, name := range names {
			maps[i].Peers = append(maps[i].Peers, peerNameNode(j+1, name))
		}

		for j := range 16 {
			maps[i].Peers = append(maps[i].Peers, peerNameNode(100+j, fmt.Sprintf("outside-%d", j)))
		}

		clients[i].UpdateFullNetmap(maps[i])
		references[i].UpdateFullNetmap(maps[i])
	}

	var errors [2][]string

	for run := range 2 {
		for i := range clients {
			publish(i)
		}

		publish(0, "peer-1")

		recorder := &peerNameAssertionRecorder{TB: t, afterError: func(n int) {
			switch n {
			case 1:
				publish(0, "peer-2")
				publish(1, "peer-0")
			case 2:
				publish(2, "peer-0")
				clients[1].UpdateFullNetmap(nil)
				references[1].UpdateFullNetmap(nil)
			}
		}}
		if run == 0 {
			assertSymmetricVisibilityReference(recorder, references)
		} else {
			servertest.AssertSymmetricVisibility(recorder, clients)
		}

		errors[run] = recorder.errors
	}

	assert.Len(t, errors[0], 2)
	assert.Equal(t, errors[0], errors[1])
}
