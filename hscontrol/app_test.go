package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	h := rec.Result().Header
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "frame-ancestors 'none'", h.Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
}

func TestNewHeadscaleFreezesDNS(t *testing.T) {
	for _, mode := range []string{"magic", "disabled", "nil"} {
		t.Run(mode, func(t *testing.T) {
			wire := &tailcfg.DNSConfig{
				Proxied: mode == "magic",
				Routes: map[string][]*dnstype.Resolver{
					"split.test": {{Addr: "1.1.1.1"}},
				},
			}
			if mode == "nil" {
				wire = nil
			}

			app := createTestApp(t, func(cfg *types.Config) {
				cfg.PrefixV4 = new(netip.MustParsePrefix("100.64.0.0/10"))
				cfg.PrefixV6 = new(netip.MustParsePrefix("fd7a:115c:a1e0::/48"))
				cfg.TailcfgDNSConfig = wire
				cfg.DNSConfig.ExtraRecordsPath = "original.json"
			})
			app.cfg.DNSConfig.ExtraRecordsPath = "changed.json"
			view := app.state.Snapshot().DNS()
			assert.Equal(t, "original.json", view.ExtraRecordsPath())

			out := view.AsStruct()
			if mode == "nil" {
				require.Nil(t, out)
				return
			}

			require.Len(t, wire.Routes, 1, "startup must not mutate the builder")
			assert.Equal(t, []*dnstype.Resolver{{Addr: "1.1.1.1"}}, out.Routes["split.test"])

			for _, zone := range []string{"64.100.in-addr.arpa", "127.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"} {
				resolvers, ok := out.Routes[zone]
				assert.Equal(t, mode == "magic", ok, zone)

				if ok {
					assert.NotNil(t, resolvers)
					assert.Empty(t, resolvers)
				}
			}
		})
	}
}
