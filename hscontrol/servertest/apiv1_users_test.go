package servertest_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

// TestAPIv1UserNames pins that an API create or rename never produces a
// name another user already holds: both answer 409 and change nothing,
// while a normal rename answers with the renamed user. OIDC users may
// share a name, so the users standing in for them here are created with
// their provider set, the way a login does.
func TestAPIv1UserNames(t *testing.T) {
	srv := servertest.NewServer(t)
	owner := srv.CreateUser(t, "names-owner")
	apiKey := srv.CreateAPIKey(t, owner)

	httpc := &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}

	call := func(method, path string, body []byte) (int, []byte) {
		t.Helper()

		req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpc.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		out, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		return resp.StatusCode, out
	}

	oidcUser := func(name, identifier string) {
		t.Helper()

		_, err := srv.State().CreateUser(types.User{
			Name:               name,
			Provider:           util.RegisterMethodOIDC,
			ProviderIdentifier: sql.NullString{String: identifier, Valid: true},
		})
		require.NoError(t, err)
	}

	usersNamed := func(name string) int {
		t.Helper()

		users, err := srv.State().ListUsersWithFilter(&types.User{Name: name})
		require.NoError(t, err)

		return len(users)
	}

	oidcUser("held-by-two", "/oidc#one")
	oidcUser("held-by-two", "/oidc#two")
	oidcUser("held-by-one", "/oidc#three")

	t.Run("create answers 409 when one OIDC user holds the name", func(t *testing.T) {
		status, out := call(http.MethodPost, "/api/v1/user", []byte(`{"name":"held-by-one"}`))
		require.Equal(t, http.StatusConflict, status, string(out))
		require.Equal(t, 1, usersNamed("held-by-one"), "nothing is changed")
	})

	t.Run("create answers 409 when two OIDC users hold the name", func(t *testing.T) {
		status, out := call(http.MethodPost, "/api/v1/user", []byte(`{"name":"held-by-two"}`))
		require.Equal(t, http.StatusConflict, status, string(out))
		require.Equal(t, 2, usersNamed("held-by-two"), "nothing is changed")
	})

	status, out := call(http.MethodPost, "/api/v1/user", []byte(`{"name":"mover"}`))
	require.Equal(t, http.StatusOK, status, string(out))

	var created struct {
		User struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal(out, &created))
	moverID, err := strconv.ParseUint(created.User.ID, 10, 32)
	require.NoError(t, err)

	t.Run("rename answers 409 onto a held name and keeps the old name", func(t *testing.T) {
		path := fmt.Sprintf("/api/v1/user/%d/rename/held-by-one", moverID)
		status, out := call(http.MethodPost, path, nil)
		require.Equal(t, http.StatusConflict, status, string(out))

		renamed, err := srv.State().GetUserByID(types.UserID(moverID))
		require.NoError(t, err)
		require.Equal(t, "mover", renamed.Name, "the user keeps its old name")
	})

	t.Run("rename answers with the renamed user", func(t *testing.T) {
		path := fmt.Sprintf("/api/v1/user/%d/rename/moved", moverID)
		status, out := call(http.MethodPost, path, nil)
		require.Equal(t, http.StatusOK, status, string(out))

		require.NoError(t, json.Unmarshal(out, &created))
		require.Equal(t, "moved", created.User.Name, "the response carries the renamed user")

		renamed, err := srv.State().GetUserByID(types.UserID(moverID))
		require.NoError(t, err)
		require.Equal(t, "moved", renamed.Name)
	})
}
