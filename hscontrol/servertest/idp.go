package servertest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// MockIDP is the smallest identity provider headscale's OIDC flow can
// run against: a discovery document, one RSA signing key on a JWKS
// endpoint, an authorization endpoint that issues codes, and a token
// endpoint that answers them with an ID token carrying the claims set
// by the test.
//
// What it deliberately does not implement, so a test cannot come to
// rely on it: signature rotation, expiry or revocation, the userinfo
// endpoint (headscale reads the claims from the ID token), the
// end-session flow, and any validation of the redirect URI, the scopes
// or PKCE — headscale sends them, the mock takes them.
type MockIDP struct {
	URL string

	mu     sync.Mutex
	key    *rsa.PrivateKey
	claims map[string]any
	// nonces are the nonces the authorization requests carried, by the
	// code they were issued with, so the ID token can carry them back.
	nonces map[string]string
	server *http.Server
}

// mockIDPKey is the one signing key every mock provider uses: the front
// door starts one per case, and a key generation each would cost more
// than the flow it drives.
var mockIDPKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("servertest: generating the identity provider key: %v", err))
	}

	return key
})

// NewMockIDP starts the provider. Close it with Close.
func NewMockIDP() *MockIDP {
	idp := &MockIDP{key: mockIDPKey(), claims: map[string]any{"sub": "mock-user"}, nonces: map[string]string{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("/authorize", idp.authorize)
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/jwks.json", idp.jwks)

	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("servertest: listening for the identity provider: %v", err))
	}

	idp.URL = "http://" + ln.Addr().String()
	idp.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() { _ = idp.server.Serve(ln) }()

	return idp
}

// Close stops the provider.
func (idp *MockIDP) Close() {
	_ = idp.server.Close()
}

// SetClaims sets the claims the next ID token carries.
func (idp *MockIDP) SetClaims(claims map[string]any) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	idp.claims = claims
}

func (idp *MockIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                idp.URL,
		"authorization_endpoint":                idp.URL + "/authorize",
		"token_endpoint":                        idp.URL + "/token",
		"jwks_uri":                              idp.URL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}

	writeJSON(w, doc)
}

// writeJSON writes v as the endpoint's answer.
func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// authorize issues a code and redirects back to the caller's redirect
// URI, as a provider does; the state rides along untouched.
func (idp *MockIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	code := fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:16]

	idp.mu.Lock()
	idp.nonces[code] = q.Get("nonce")
	idp.mu.Unlock()

	out := back.Query()
	out.Set("code", code)
	out.Set("state", q.Get("state"))
	back.RawQuery = out.Encode()

	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // the mock redirects where the caller asked
}

func (idp *MockIDP) token(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()

	claims := make(map[string]any, len(idp.claims)+2)
	maps.Copy(claims, idp.claims)

	nonce := idp.nonces[r.FormValue("code")]
	delete(idp.nonces, r.FormValue("code"))

	idp.mu.Unlock()

	if nonce != "" {
		claims["nonce"] = nonce
	}

	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Hour).Unix()
	claims["iss"] = idp.URL
	claims["aud"] = "headscale"

	token, err := idp.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	writeJSON(w, map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"id_token":     token,
	})
}

func (idp *MockIDP) sign(claims map[string]any) (string, error) {
	enc := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}

		return base64.RawURLEncoding.EncodeToString(b), nil
	}

	h, err := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}

	c, err := enc(claims)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(h + "." + c))

	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}

	return h + "." + c + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (idp *MockIDP) jwks(w http.ResponseWriter, _ *http.Request) {
	type key struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	writeJSON(w, map[string]any{
		"keys": []key{{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "mock-1",
			N: base64.RawURLEncoding.EncodeToString(idp.key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}},
	})
}
