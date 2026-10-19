package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

// TestGenerateRegionInsecureTLS pins the contract nix/testkit.nix relies on:
// with the knob set, the embedded node advertises the TLS listener's port and
// InsecureForTests, so clients without the self-signed cert can relay.
func TestGenerateRegionInsecureTLS(t *testing.T) {
	tests := []struct {
		name         string
		knob         string
		wantPort     int
		wantInsecure bool
		wantErr      bool
	}{
		{name: "unset keeps server_url port", knob: "", wantPort: 80},
		{
			name:         "set advertises TLS port",
			knob:         "[::]:443",
			wantPort:     443,
			wantInsecure: true,
		},
		{name: "named port", knob: ":https", wantPort: 443, wantInsecure: true},
		{name: "random port is refused", knob: ":0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", tt.knob)
			t.Cleanup(
				func() { envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", "") },
			)

			d := &DERPServer{
				serverURL: "http://headscale",
				cfg: &types.DERPConfig{
					ServerRegionID:   999,
					ServerRegionCode: "headscale",
					STUNAddr:         "[::]:3478",
				},
			}

			region, err := d.GenerateRegion()
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Len(t, region.Nodes, 1)

			node := region.Nodes[0]
			assert.Equal(t, "headscale", node.HostName)
			assert.Equal(t, tt.wantPort, node.DERPPort)
			assert.Equal(t, tt.wantInsecure, node.InsecureForTests)
			assert.Equal(t, 3478, node.STUNPort)
		})
	}
}

// TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates guards against the handler
// resolving a DERP map captured at startup: hostnames that a later
// auto-update adds must be served.
func TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates(t *testing.T) {
	var current atomic.Pointer[tailcfg.DERPMap]
	current.Store(&tailcfg.DERPMap{})

	handler := DERPBootstrapDNSHandler(func() tailcfg.DERPMapView {
		return current.Load().View()
	})

	current.Store(
		&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID: 1,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", RegionID: 1, HostName: "localhost"},
				},
			},
		}},
	)

	rec := httptest.NewRecorder()
	handler(
		rec,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"/bootstrap-dns",
			nil,
		),
	)

	var got map[string][]net.IP
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Contains(t, got, "localhost")
}

var stunLoopbackCases = []struct {
	name, serverNetwork, serverIP, clientNetwork, clientIP string
}{
	{"ipv4", "udp4", "127.0.0.1", "udp4", "127.0.0.1"},
	{"ipv6", "udp6", "::1", "udp6", "::1"},
	{"mapped-dualstack", "udp", "::", "udp4", "127.0.0.1"},
}

func listenSTUNLoopback(tb testing.TB, network, ip string) *net.UDPConn {
	tb.Helper()

	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil &&
		(errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
		tb.Skipf("loopback address family unavailable: %v", err)
	}

	require.NoError(tb, err)
	tb.Cleanup(func() { conn.Close() })

	return conn
}

func runSTUNLoopback(
	tb testing.TB,
	conn *net.UDPConn,
	listener func(context.Context, *net.UDPConn),
) {
	tb.Helper()
	ctx, cancel := context.WithCancel(tb.Context())

	done := make(chan struct{})
	go func() {
		defer close(done)

		listener(ctx, conn)
	}()

	tb.Cleanup(func() {
		cancel()
		conn.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			tb.Error("STUN listener did not stop after cancellation and socket close")
		}
	})
}

func TestSTUNUDPAddressRepresentations(t *testing.T) {
	for _, tc := range stunLoopbackCases {
		t.Run(tc.name, func(t *testing.T) {
			server := listenSTUNLoopback(t, tc.serverNetwork, tc.serverIP)
			client := listenSTUNLoopback(t, tc.clientNetwork, tc.clientIP)
			serverAddr, ok := server.LocalAddr().(*net.UDPAddr)
			require.True(t, ok)

			target := netip.AddrPortFrom(
				netip.MustParseAddr(tc.clientIP),
				serverAddr.AddrPort().Port(),
			)

			require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))

			_, err := client.WriteToUDPAddrPort([]byte{1}, target)
			require.NoError(t, err)

			var buf [1]byte

			_, old, err := server.ReadFromUDP(buf[:])
			require.NoError(t, err)
			_, err = client.WriteToUDPAddrPort([]byte{1}, target)
			require.NoError(t, err)
			_, current, err := server.ReadFromUDPAddrPort(buf[:])
			require.NoError(t, err)

			addr, ok := netip.AddrFromSlice(old.IP)
			require.True(t, ok)
			require.Equal(
				t,
				netip.AddrPortFrom(addr, uint16(old.Port)), //nolint:gosec // ReadFromUDP returns a port within uint16 range.
				current,
			)

			if tc.name == "mapped-dualstack" {
				require.True(t, current.Addr().Is4In6())
			}
		})
	}

	t.Run("zone does not change STUN payload", func(t *testing.T) {
		original := &net.UDPAddr{IP: net.ParseIP("fe80::1234"), Port: 3478, Zone: "lo"}
		addr, ok := netip.AddrFromSlice(original.IP)
		require.True(t, ok)

		current := original.AddrPort()
		require.Equal(t, "lo", current.Addr().Zone())
		require.Equal(
			t,
			stun.Response(stun.TxID{}, netip.AddrPortFrom(addr, 3478)),
			stun.Response(stun.TxID{}, current),
		)
	})
}

func TestSTUNListenerMatchesOriginal(t *testing.T) {
	previousLogger := log.Logger
	log.Logger = zerolog.Nop()

	t.Cleanup(func() { log.Logger = previousLogger })

	for _, tc := range stunLoopbackCases {
		t.Run(tc.name, func(t *testing.T) {
			client := listenSTUNLoopback(t, tc.clientNetwork, tc.clientIP)

			var original [][]byte

			allocations := make(map[string]float64)

			for _, impl := range []struct {
				name   string
				listen func(context.Context, *net.UDPConn)
			}{{"original", originalServerSTUNListener}, {"current", serverSTUNListener}} {
				t.Run(impl.name, func(t *testing.T) {
					server := listenSTUNLoopback(t, tc.serverNetwork, tc.serverIP)
					serverAddr, ok := server.LocalAddr().(*net.UDPAddr)
					require.True(t, ok)
					clientAddr, ok := client.LocalAddr().(*net.UDPAddr)
					require.True(t, ok)

					target := netip.AddrPortFrom(
						netip.MustParseAddr(tc.clientIP),
						serverAddr.AddrPort().Port(),
					)

					runSTUNLoopback(t, server, impl.listen)
					require.NoError(
						t,
						client.SetReadDeadline(time.Now().Add(5*time.Second)),
					)

					badFingerprint := stun.Request(stun.TxID{9})

					badFingerprint[len(badFingerprint)-1] ^= 1
					for _, invalid := range [][]byte{nil, []byte("not STUN"), badFingerprint, stun.Response(stun.TxID{}, target)} {
						_, err := client.WriteToUDPAddrPort(invalid, target)
						require.NoError(t, err)
					}

					responses := make([][]byte, 0, 2)

					for _, tx := range []stun.TxID{{1, 2, 3}, {4, 5, 6}} {
						_, err := client.WriteToUDPAddrPort(stun.Request(tx), target)
						require.NoError(t, err)

						var buf [128]byte

						n, _, err := client.ReadFromUDPAddrPort(buf[:])
						require.NoError(t, err)
						gotTx, gotAddr, err := stun.ParseResponse(buf[:n])
						require.NoError(t, err)
						require.Equal(t, tx, gotTx)
						require.Equal(
							t,
							clientAddr.AddrPort(),
							gotAddr,
						)

						responses = append(responses, bytes.Clone(buf[:n]))
					}

					if impl.name == "original" {
						original = responses
					} else {
						require.Equal(t, original, responses)
					}

					require.NoError(
						t,
						client.SetReadDeadline(time.Now().Add(20*time.Millisecond)),
					)

					var buf [128]byte

					_, _, err := client.ReadFromUDPAddrPort(buf[:])

					var timeout net.Error
					require.ErrorAs(t, err, &timeout)
					require.True(
						t,
						timeout.Timeout(),
						"invalid packets must not receive replies",
					)

					require.NoError(
						t,
						client.SetReadDeadline(time.Now().Add(5*time.Second)),
					)

					packet := stun.Request(stun.TxID{4, 5, 6})
					allocations[impl.name] = testing.AllocsPerRun(100, func() {
						_, err := client.WriteToUDPAddrPort(
							packet,
							target,
						)
						if err != nil {
							t.Fatal(err)
						}

						n, _, err := client.ReadFromUDPAddrPort(buf[:])
						if err != nil {
							t.Fatal(err)
						}

						if !bytes.Equal(responses[1], buf[:n]) {
							t.Fatal("STUN response changed during allocation check")
						}
					})
				})
			}

			t.Logf(
				"allocs/roundtrip: original=%g current=%g",
				allocations["original"],
				allocations["current"],
			)
			require.Less(t, allocations["current"], allocations["original"])
		})
	}
}

func BenchmarkSTUNListener(b *testing.B) {
	previousLogger := log.Logger
	log.Logger = zerolog.Nop()

	b.Cleanup(func() { log.Logger = previousLogger })

	for _, tc := range stunLoopbackCases {
		for _, impl := range []struct {
			name   string
			listen func(context.Context, *net.UDPConn)
		}{{"original", originalServerSTUNListener}, {"current", serverSTUNListener}} {
			b.Run(tc.name+"/"+impl.name, func(b *testing.B) {
				server := listenSTUNLoopback(b, tc.serverNetwork, tc.serverIP)
				client := listenSTUNLoopback(b, tc.clientNetwork, tc.clientIP)
				serverAddr, ok := server.LocalAddr().(*net.UDPAddr)
				require.True(b, ok)

				target := netip.AddrPortFrom(
					netip.MustParseAddr(tc.clientIP),
					serverAddr.AddrPort().Port(),
				)

				runSTUNLoopback(b, server, impl.listen)
				require.NoError(b, client.SetDeadline(time.Now().Add(time.Minute)))

				packet := stun.Request(stun.TxID{1, 2, 3})
				_, err := client.WriteToUDPAddrPort(packet, target)
				require.NoError(b, err)

				var buf [128]byte

				n, _, err := client.ReadFromUDPAddrPort(buf[:])
				require.NoError(b, err)

				want := bytes.Clone(buf[:n])

				b.ReportAllocs()
				b.SetBytes(int64(len(packet) + len(want)))

				for b.Loop() {
					_, err := client.WriteToUDPAddrPort(packet, target)
					if err != nil {
						b.Fatal(err)
					}

					n, _, err := client.ReadFromUDPAddrPort(buf[:])
					if err != nil {
						b.Fatal(err)
					}

					if !bytes.Equal(want, buf[:n]) {
						b.Fatal("STUN response changed")
					}
				}
			})
		}
	}
}

// Frozen from 1096abfc8 before changing the UDP address representation.
func originalServerSTUNListener(ctx context.Context, packetConn *net.UDPConn) {
	var buf [64 << 10]byte

	for {
		bytesRead, udpAddr, err := packetConn.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			log.Error().Caller().Err(err).Msgf("stun ReadFrom")

			// Rate limit error logging - wait before retrying, but respect context cancellation
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}

			continue
		}

		log.Trace().Caller().Msgf("stun request from %v", udpAddr)

		pkt := buf[:bytesRead]
		if !stun.Is(pkt) {
			log.Trace().Caller().Msgf("udp packet is not stun")

			continue
		}

		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("stun parse error")

			continue
		}

		addr, _ := netip.AddrFromSlice(udpAddr.IP)
		res := stun.Response(txid, netip.AddrPortFrom(addr, uint16(udpAddr.Port))) //nolint:gosec // port is always <=65535

		_, err = packetConn.WriteTo(res, udpAddr)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("issue writing to UDP")

			continue
		}
	}
}
