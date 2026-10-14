package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gigahost "github.com/kradalby/libdns-gigahost"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/libdns/rfc2136"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noEnv(string) (any, bool) { return nil, false }

func envOf(m map[string]any) func(string) (any, bool) {
	return func(k string) (any, bool) {
		v, ok := m[k]

		return v, ok
	}
}

func TestNewProvider(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte("from-file\n"), 0o600))

	tests := []struct {
		name     string
		provider string
		settings map[string]any
		env      map[string]any
		want     Provider
		wantErr  error
	}{
		{
			name:     "cloudflare from settings",
			provider: "cloudflare",
			settings: map[string]any{"name": "cloudflare", "api_token": "tok"},
			want:     &cloudflare.Provider{APIToken: "tok"},
		},
		{
			name:     "name is case insensitive",
			provider: "CloudFlare",
			settings: map[string]any{"api_token": "tok"},
			want:     &cloudflare.Provider{APIToken: "tok"},
		},
		{
			name:     "env overrides file value",
			provider: "cloudflare",
			settings: map[string]any{"api_token": "from-yaml"},
			env:      map[string]any{"api_token": "from-env"},
			want:     &cloudflare.Provider{APIToken: "from-env"},
		},
		{
			name:     "env only",
			provider: "rfc2136",
			env: map[string]any{
				"server":   "ns1.example.com:53",
				"key_name": "headscale",
				"key_alg":  "hmac-sha256",
				"key":      "c2VjcmV0",
			},
			want: &rfc2136.Provider{
				Server:  "ns1.example.com:53",
				KeyName: "headscale",
				KeyAlg:  "hmac-sha256",
				Key:     "c2VjcmV0",
			},
		},
		{
			name:     "secret from path",
			provider: "cloudflare",
			settings: map[string]any{"api_token_path": secret},
			want:     &cloudflare.Provider{APIToken: "from-file"},
		},
		{
			name:     "secret path from env",
			provider: "cloudflare",
			env:      map[string]any{"api_token_path": secret},
			want:     &cloudflare.Provider{APIToken: "from-file"},
		},
		{
			name:     "value and path both set",
			provider: "cloudflare",
			settings: map[string]any{"api_token": "tok", "api_token_path": secret},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unreadable path",
			provider: "cloudflare",
			settings: map[string]any{"api_token_path": filepath.Join(t.TempDir(), "missing")},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unknown key",
			provider: "cloudflare",
			settings: map[string]any{"auth_token": "tok"},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unknown provider",
			provider: "route53",
			wantErr:  ErrUnknownProvider,
		},
		{
			name:     "gigahost",
			provider: "gigahost",
			settings: map[string]any{"api_key_path": secret},
			want:     &gigahost.Provider{APIKey: "from-file"},
		},
		{
			name:     "webhook",
			provider: "webhook",
			settings: map[string]any{"url": "https://dns.example.com/hook", "username": "hs"},
			want:     &WebhookProvider{URL: "https://dns.example.com/hook", Username: "hs"},
		},
		{
			name:     "only a name",
			provider: "gigahost",
			settings: map[string]any{"name": "gigahost"},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "webhook without url",
			provider: "webhook",
			wantErr:  ErrProviderConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			get := noEnv
			if tt.env != nil {
				get = envOf(tt.env)
			}

			got, err := NewProvider(tt.provider, tt.settings, get)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWebhookProvider(t *testing.T) {
	type call struct {
		path, user, pass string
		msg              webhookMessage
	}

	var (
		mu    sync.Mutex
		calls []call
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg webhookMessage

		err := json.NewDecoder(r.Body).Decode(&msg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		user, pass, _ := r.BasicAuth()

		mu.Lock()

		calls = append(calls, call{path: r.URL.Path, user: user, pass: pass, msg: msg})
		mu.Unlock()

		if msg.Value == "fail" {
			http.Error(w, "no such zone", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := &WebhookProvider{URL: srv.URL + "/hook/", Username: "hs", Password: "pw"}
	rec := libdns.TXT{Name: "_acme-challenge.node", TTL: time.Minute, Text: "value"}
	ctx := context.Background()

	got, err := p.AppendRecords(ctx, "ts.example.com.", []libdns.Record{rec})
	require.NoError(t, err)
	assert.Equal(t, []libdns.Record{rec}, got, "certmagic needs the input record back unchanged")

	_, err = p.DeleteRecords(ctx, "ts.example.com.", []libdns.Record{rec})
	require.NoError(t, err)

	want := webhookMessage{FQDN: "_acme-challenge.node.ts.example.com.", Value: "value"}
	assert.Equal(t, []call{
		{path: "/hook/present", user: "hs", pass: "pw", msg: want},
		{path: "/hook/cleanup", user: "hs", pass: "pw", msg: want},
	}, calls)

	_, err = p.AppendRecords(ctx, "ts.example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node", Text: "fail"},
	})
	require.ErrorIs(t, err, errWebhookStatus)
	require.ErrorContains(t, err, "no such zone")

	_, err = p.AppendRecords(ctx, "ts.example.com.", []libdns.Record{
		libdns.Address{Name: "node"},
	})
	require.ErrorIs(t, err, errWebhookRecordType)
}
