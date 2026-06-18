package integration

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAuthApproveRejectCommand exercises `headscale auth approve` and
// `headscale auth reject` over the gRPC transport.
//
// Both commands operate on a *pending* interactive auth session keyed by an
// auth-id and finish its verdict (hscontrol/grpcv1.go AuthApprove/AuthReject).
// The happy path is intentionally not asserted end-to-end: an approve carries
// an empty verdict that does not itself register a node — the waiting client is
// instructed to restart registration (hscontrol/auth.go waitForFollowup), so a
// driven web-login would simply hang. Completing an interactive registration to
// a real node is covered by `auth register` in the node tests. What we guard
// here is that both commands round-trip to their gRPC handlers and surface the
// handlers' validation:
//
//   - a malformed auth-id is rejected with "invalid auth_id"
//   - a well-formed but unknown auth-id is rejected with "no pending auth session"
//
// `auth register` is covered separately (cli_nodes_test.go and the web-auth
// flow tests).
func TestAuthApproveRejectCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-auth", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// A well-formed (correct prefix/length) but unknown auth-id: the handler
	// reaches the cache lookup and reports no pending session.
	unknownAuthID := types.MustAuthID().String()

	for _, sub := range []string{"approve", "reject"} {
		// Malformed auth-id: rejected before the cache lookup.
		_, err := headscale.Execute([]string{
			"headscale", "auth", sub,
			"--auth-id", "not-a-valid-auth-id",
		})
		require.ErrorContains(t, err, "invalid auth_id",
			"auth %s must reject a malformed auth-id", sub)

		// Well-formed but unknown auth-id: rejected at the cache lookup.
		_, err = headscale.Execute([]string{
			"headscale", "auth", sub,
			"--auth-id", unknownAuthID,
		})
		require.ErrorContains(t, err, "no pending auth session",
			"auth %s must report a missing pending session", sub)
	}
}
