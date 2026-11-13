package apiv2

import (
	"database/sql"
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

// TestMapErrorClassifiesPolicyRevalidation keeps drift refusals in the policy
// envelope while preserving genuine storage failures as server errors.
func TestMapErrorClassifiesPolicyRevalidation(t *testing.T) {
	refusal := mapError("setting policy", fmt.Errorf("revalidating live inputs: %w: unknown owner", state.ErrInvalidPolicy))

	var policyError *apiError
	require.ErrorAs(t, refusal, &policyError, "a refused candidate uses the policy error envelope")
	assert.Equal(t, 400, policyError.GetStatus())
	assert.Contains(t, policyError.Message, "unknown owner")

	storage := mapError("setting policy", sql.ErrConnDone)
	status, ok := storage.(interface{ GetStatus() int })
	require.True(t, ok)
	assert.Equal(t, 500, status.GetStatus(), "SQL failure is not a refused candidate")
}
