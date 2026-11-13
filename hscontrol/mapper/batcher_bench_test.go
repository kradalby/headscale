package mapper

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// The old Batcher ingress/connection benchmarks now measure the Hub operations
// that replace their queues. End-to-end rendering is BenchmarkScalingWrites.
func BenchmarkHubOperations(b *testing.B) {
	for _, n := range []types.NodeID{10, 1000, 10000} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			h := NewHub()
			defer h.Close()

			for i := range n {
				h.Join(i+1, func() {})
			}

			b.Run("connected", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					_ = h.IsConnected(1)
				}
			})
			b.Run("connections", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					_ = h.Connected()
				}
			})
			b.Run("targeted-wake", func(b *testing.B) {
				wake := map[types.NodeID]struct{}{1: {}}

				b.ReportAllocs()

				for b.Loop() {
					h.wake(false, wake)
				}
			})
			b.Run("broadcast-wake", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					h.wake(true, nil)
				}
			})
			b.Run("connection-churn", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					sess := h.Join(n+1, func() {})
					h.Leave(sess)
				}
			})
			b.Run("ping", func(b *testing.B) {
				sess := h.Join(1, func() {})
				pr := &tailcfg.PingRequest{}

				b.ReportAllocs()

				for b.Loop() {
					h.Ping(1, pr)
					<-sess.Pings()
				}
			})
			b.Run("concurrent-wake-and-churn", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						sess := h.Join(n+1, func() {})
						h.wake(false, map[types.NodeID]struct{}{1: {}})
						h.Leave(sess)
					}
				})
			})
		})
	}
}

// stunReportRun drains every report immediately, leaving no coalescing window.
// Main's legacy gate emitted zero frames for this additional/replaced STUN
// endpoint. The graph deliberately publishes its complete current raw set.
type stunReportRun struct {
	*scalingRun

	reporter types.NodeID
	req      tailcfg.MapRequest
	frames   int
	encodes  int
	wire     int
}

func newSTUNReportRun(tb testing.TB, visible, unrelated int, router bool) *stunReportRun {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database:  types.DatabaseConfig{Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/h.db"}},
		ServerURL: "https://headscale.test", Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		Prefixes:  types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential},
		DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}
	cfg.Database.Sqlite.WriteAheadLog = true
	cfg.Database.Sqlite.WALAutoCheckPoint = 1000
	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	var mode string

	var synchronous int

	require.NoError(tb, database.DB.Raw("PRAGMA journal_mode").Scan(&mode).Error)
	require.Equal(tb, "wal", mode)
	require.NoError(tb, database.DB.Raw("PRAGMA synchronous").Scan(&synchronous).Error)
	require.Equal(tb, 1, synchronous)

	owner := database.CreateUserForTest("endpoint-owner")

	peers := database.CreateRegisteredNodesForTest(owner, visible+1, "visible")
	if unrelated > 0 {
		other := database.CreateUserForTest("unrelated-owner")
		database.CreateRegisteredNodesForTest(other, unrelated, "hidden")
	}

	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	require.NoError(tb, s.DB().DB.Raw("PRAGMA journal_mode").Scan(&mode).Error)
	require.Equal(tb, "wal", mode)
	require.NoError(tb, s.DB().DB.Raw("PRAGMA synchronous").Scan(&synchronous).Error)
	require.Equal(tb, 1, synchronous)
	tb.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(ownUserOnly))
	require.NoError(tb, err)

	reporter := peers[0].ID
	s.Connect(reporter)
	node := mustNode(tb, s, reporter)

	hi := &tailcfg.Hostinfo{Hostname: node.Hostname(), NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}}
	if router {
		hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")}
	}

	req := tailcfg.MapRequest{
		NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Hostinfo: hi,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}, EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointLocal},
	}
	require.NoError(tb, s.UpdateNodeFromMapRequest(reporter, req))

	if router {
		_, err = s.SetApprovedRoutes(reporter, hi.RoutableIPs)
		require.NoError(tb, err)
	}

	h := NewHub()
	tb.Cleanup(h.Close)

	streams := make([]*Stream, 0, visible+unrelated+1)

	for _, nv := range s.ListNodes().All() {
		st := NewStream(cfg, h, nv.ID(), capVer)
		st.Attach(h.Join(nv.ID(), func() {}))
		_, err = st.Initial(s.Snapshot())
		require.NoError(tb, err)
		st.Delivered()
		streams = append(streams, st)
	}

	return &stunReportRun{scalingRun: newScalingRun(s, streams), reporter: reporter, req: req}
}

func (run *stunReportRun) report(tb testing.TB, iteration int) {
	tb.Helper()
	// Alternate a single STUN address; all reported sets include the same
	// useful local endpoint, so the legacy gate remains false every time.
	run.req.Endpoints = []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:41641"),
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), uint16(20000+iteration%2)),
	}
	run.req.EndpointTypes = []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN}

	err := run.s.UpdateNodeFromMapRequest(run.reporter, run.req)
	if err != nil {
		tb.Fatal(err)
	}

	snap := run.s.Snapshot()
	all, wake := Route(run.last, snap, snap.Since(run.last))
	run.last = snap

	if all {
		tb.Fatal("one ordinary endpoint report became a global broadcast")
	}

	h := run.streams[0].hub
	h.wake(false, wake)

	for id := range wake {
		st := run.byNode[id]
		if st == nil {
			tb.Fatalf("unexpected recipient %d", id)
		}

		select {
		case <-st.sess.Wakes():
		default:
			tb.Fatalf("recipient %d was not scheduled", id)
		}

		run.woken++
		before := st.r.rendered

		out, err := st.Update(snap)
		if err != nil {
			tb.Fatal(err)
		}

		if len(out) > 0 {
			run.updates++
		}

		for _, response := range out {
			run.frames++

			wire, err := h.Encode(response, false, func(response *tailcfg.MapResponse, compress bool) ([]byte, error) {
				run.encodes++
				return benchEncode(response, compress)
			})
			if err != nil {
				tb.Fatal(err)
			}

			run.wire += len(wire)
		}

		st.Delivered()
		run.rendered += st.r.rendered - before
	}
}

func TestSTUNReportFastDrainWork(t *testing.T) {
	const reports = 4

	for _, visible := range []int{1, 4} {
		for _, unrelated := range []int{0, 40} {
			for _, router := range []bool{false, true} {
				t.Run(fmt.Sprintf("visible=%d/unrelated=%d/router=%t", visible, unrelated, router), func(t *testing.T) {
					run := newSTUNReportRun(t, visible, unrelated, router)
					for i := range reports {
						run.report(t, i)
					}

					require.Equal(t, reports*(visible+1), run.woken)
					require.Equal(t, run.woken, run.updates)
					require.Equal(t, run.woken, run.frames)
					require.Equal(t, reports*visible, run.rendered)
					require.Equal(t, reports*2, run.encodes, "one shared peer patch plus one self frame per report")
					require.Positive(t, run.wire)
					run.requireSettled(t, "endpoint")

					for _, st := range run.streams {
						require.Empty(t, st.sess.wakes, "unrelated sessions must accumulate no work")
					}
				})
			}
		}
	}
}

func BenchmarkSTUNEndpointReports(b *testing.B) {
	for _, visible := range []int{1, 10, 100} {
		for _, unrelated := range []int{0, 1000} {
			for _, router := range []bool{false, true} {
				b.Run(fmt.Sprintf("visible=%d/unrelated=%d/router=%t", visible, unrelated, router), func(b *testing.B) {
					run := newSTUNReportRun(b, visible, unrelated, router)
					b.ReportAllocs()

					var reports int
					for b.Loop() {
						run.report(b, reports)
						reports++
					}

					run.requireSettled(b, "endpoint")
					b.ReportMetric(float64(run.woken)/float64(reports), "woken/op")
					b.ReportMetric(float64(run.frames)/float64(reports), "frames/op")
					b.ReportMetric(float64(run.encodes)/float64(reports), "encodes/op")
					b.ReportMetric(float64(run.rendered)/float64(reports), "peer-renders/op")
					b.ReportMetric(float64(run.wire)/float64(reports), "wire-B/op")
					b.ReportMetric(0, "legacy-eager-frames/op")
				})
			}
		}
	}
}
