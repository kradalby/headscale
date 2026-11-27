package servertest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
)

var (
	errNoRedirect = errors.New("servertest: not following the redirect")

	// errNoRedirect stops an HTTP client at a redirect, handing the
	// caller the Location it stopped at. The rest are the flow's own
	// steps going wrong.
	errNoResponse         = errors.New("servertest: no response")
	errRegisterNoRedirect = errors.New("servertest: the register page does not redirect to the identity provider")
	errIDPNoRedirect      = errors.New("servertest: the identity provider does not redirect back")
	errNoConfirmation     = errors.New("servertest: the callback does not reach the confirmation page")
	errNoCSRFCookie       = errors.New("servertest: the confirmation cookie the callback set")
)

// DriveOIDCLogin completes the interactive login waiting on authID
// through the real callback, as a person does: the register page's
// redirect to the identity provider, the code the provider issues with
// the claims set on it, and the callback on the server that exchanges
// the code for the claims and registers the node.
func DriveOIDCLogin(tb testing.TB, srv *TestServer, idp *MockIDP, authID string) error {
	tb.Helper()

	_, err := types.AuthIDFromString(authID)
	if err != nil {
		return fmt.Errorf("the auth id: %w", err)
	}

	plain := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return errNoRedirect },
		Timeout:       10 * time.Second,
	}

	jar, jerr := cookiejar.New(nil)
	if jerr != nil {
		return fmt.Errorf("the cookie jar: %w", jerr)
	}

	mem := &http.Client{
		Transport:     &http.Transport{DialContext: srv.MemNet().Dial},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errNoRedirect },
		Jar:           jar,
		Timeout:       10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	location := func(c *http.Client, u string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}

		resp, err := c.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}

		// A redirect is not an error here: it is where the flow goes
		// next, and the client stops at it to hand the Location over.
		if err != nil && !errors.Is(err, errNoRedirect) {
			return "", err
		}

		if resp == nil {
			return "", errNoResponse
		}

		return resp.Header.Get("Location"), nil
	}

	// The register page redirects to the provider's authorization; the
	// provider redirects back with a code and the state.
	redirect, err := location(mem, srv.URL+"/register/"+url.PathEscape(authID))
	if err != nil {
		return fmt.Errorf("the register page: %w", err)
	}

	if redirect == "" {
		return errRegisterNoRedirect
	}

	back, err := location(plain, redirect)
	if err != nil {
		return fmt.Errorf("the identity provider: %w", err)
	}

	if back == "" {
		return errIDPNoRedirect
	}

	// The provider redirected to the server's own configured URL, which
	// in a test is not the one it listens on: the callback's path and
	// query are what matter, reached over the server's in-memory network.
	callback, err := url.Parse(back)
	if err != nil {
		return fmt.Errorf("the callback redirect: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+callback.Path+"?"+callback.RawQuery, nil)
	if err != nil {
		return err
	}

	resp, err := mem.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	// The callback ends in the confirmation page's redirect; the client
	// stops there to confirm.
	if err != nil && !errors.Is(err, errNoRedirect) {
		return fmt.Errorf("the callback: %w", err)
	}

	if resp == nil {
		return errNoResponse
	}

	// The callback hands the confirmation page the CSRF cookie; the
	// page the person confirms on posts it back.
	csrfURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("the confirmation redirect: %w", err)
	}

	if csrfURL.Path == "" {
		return errNoConfirmation
	}

	var csrf string

	// The cookie is scoped to the confirmation page's path; the jar
	// answers at it.
	confirmURL, err := url.Parse(srv.URL + csrfURL.Path)
	if err != nil {
		return fmt.Errorf("the confirmation URL: %w", err)
	}

	for _, c := range jar.Cookies(confirmURL) {
		if c.Name == "headscale_register_confirm" {
			csrf = c.Value
		}
	}

	if csrf == "" {
		return errNoCSRFCookie
	}

	form := url.Values{"headscale_register_confirm": {csrf}}

	confirm, err := http.NewRequestWithContext(
		ctx, http.MethodPost, srv.URL+csrfURL.Path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	confirm.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	confirmed, err := mem.Do(confirm)
	if err != nil {
		return fmt.Errorf("the confirmation: %w", err)
	}
	defer confirmed.Body.Close()

	if confirmed.StatusCode != http.StatusOK {
		return fmt.Errorf("the confirmation: %d", confirmed.StatusCode) //nolint:err113
	}

	return nil
}
