package apiv2

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMapErrorClassifiesVanishedNode pins that a node whose row a lifetime
// delete already dropped maps to 404, not 500: the v1 API and the lite map
// endpoint classify the same error as not-found.
func TestMapErrorClassifiesVanishedNode(t *testing.T) {
	err := mapError("vanishing", fmt.Errorf("setting expiry: %w", state.ErrNodeNotInNodeStore))

	statusErr, ok := err.(interface{ GetStatus() int })
	require.True(t, ok, "mapError must return a status error")
	assert.Equal(t, 404, statusErr.GetStatus())
}
