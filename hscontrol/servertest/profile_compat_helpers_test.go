package servertest_test

import (
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// Profile-comparison helpers carried over from the upstream compat suite:
// the merged lifecycle and via HA captures compare user profiles through
// them.

// viaCompatSkipReasons lists the SaaS/headscale profile differences the
// compat suites accept; only the profile checks consult it here.
var viaCompatSkipReasons = map[string]string{
	"tagged-self": "TAGGED_SELF_PROFILE: SaaS gives a tagged node a profile of its own, headscale the shared tagged-devices one",
}

// compareUserProfiles compares the profile the viewer holds for itself and
// for each peer in clients. Profile IDs differ between SaaS and headscale, so
// a profile is its login, with SaaS emails mapped to user names, and its
// display name.
func compareUserProfiles(
	t require.TestingT,
	got, want *netmap.NetworkMap,
	clients map[string]*servertest.TestClient,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	gotProfiles := nodeProfiles(got, clients)

	for name, wantProfile := range nodeProfiles(want, clients) {
		check := "peer"
		if name == "" {
			check = "self"
			if want.SelfNode.Tags().Len() > 0 {
				check = "tagged-self"
			}
		}

		if reason, listed := viaCompatSkipReasons[check]; listed {
			if gotProfiles[name] == wantProfile {
				t.Errorf("node %q: %s profile matches SaaS; delete viaCompatSkipReasons[%q] (%s)",
					name, check, check, reason)
			}

			continue
		}

		assert.Equalf(t, wantProfile, gotProfiles[name], "node %q: %s profile mismatch", name, check)
	}
}

// nodeProfiles maps "" (self) and each peer in clients to its user profile.
func nodeProfiles(
	nm *netmap.NetworkMap,
	clients map[string]*servertest.TestClient,
) map[string]string {
	profile := func(id tailcfg.UserID) string {
		p, ok := nm.UserProfiles[id]
		if !ok {
			return "no profile"
		}

		login := p.LoginName()
		if name, ok := captureUserNames[login]; ok {
			login = name
		}

		return login + " / " + p.DisplayName()
	}

	out := map[string]string{"": profile(nm.SelfNode.User())}

	for _, peer := range nm.Peers {
		name := extractHostname(peer.Name())
		if _, isOurs := clients[name]; isOurs {
			out[name] = profile(peer.User())
		}
	}

	return out
}
