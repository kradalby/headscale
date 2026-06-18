package integration

import (
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)

	count := 5

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-apikey"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	keys := make([]string, count)

	for idx := range count {
		apiResult, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"create",
				"--expiration",
				"24h",
				"--output",
				"json",
			},
		)
		require.NoError(t, err)
		assert.NotEmpty(t, apiResult)

		keys[idx] = apiResult
	}

	assert.Len(t, keys, 5)

	var listedAPIKeys []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list")

	assert.Len(t, listedAPIKeys, 5)

	assert.Equal(t, uint64(1), listedAPIKeys[0].GetId())
	assert.Equal(t, uint64(2), listedAPIKeys[1].GetId())
	assert.Equal(t, uint64(3), listedAPIKeys[2].GetId())
	assert.Equal(t, uint64(4), listedAPIKeys[3].GetId())
	assert.Equal(t, uint64(5), listedAPIKeys[4].GetId())

	assert.NotEmpty(t, listedAPIKeys[0].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[1].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[2].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[3].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[4].GetPrefix())

	assert.True(t, listedAPIKeys[0].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[1].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[2].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[3].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[4].GetExpiration().AsTime().After(time.Now()))

	assert.True(
		t,
		listedAPIKeys[0].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[1].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[2].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[3].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[4].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)

	expiredPrefixes := make(map[string]bool)

	// Expire three keys
	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"expire",
				"--prefix",
				listedAPIKeys[idx].GetPrefix(),
			},
		)
		require.NoError(t, err)

		expiredPrefixes[listedAPIKeys[idx].GetPrefix()] = true
	}

	var listedAfterExpireAPIKeys []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAfterExpireAPIKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after expire")

	for index := range listedAfterExpireAPIKeys {
		if _, ok := expiredPrefixes[listedAfterExpireAPIKeys[index].GetPrefix()]; ok {
			// Expired
			assert.True(
				t,
				listedAfterExpireAPIKeys[index].GetExpiration().AsTime().Before(time.Now()),
			)
		} else {
			// Not expired
			assert.False(
				t,
				listedAfterExpireAPIKeys[index].GetExpiration().AsTime().Before(time.Now()),
			)
		}
	}

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"delete",
			"--prefix",
			listedAPIKeys[0].GetPrefix(),
		})
	require.NoError(t, err)

	var listedAPIKeysAfterDelete []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterDelete,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after delete")

	assert.Len(t, listedAPIKeysAfterDelete, 4)

	// Test expire by ID (using key at index 0)
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"expire",
			"--id",
			strconv.FormatUint(listedAPIKeysAfterDelete[0].GetId(), 10),
		})
	require.NoError(t, err)

	var listedAPIKeysAfterExpireByID []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterExpireByID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after expire by ID")

	// Verify the key was expired
	for idx := range listedAPIKeysAfterExpireByID {
		if listedAPIKeysAfterExpireByID[idx].GetId() == listedAPIKeysAfterDelete[0].GetId() {
			assert.True(t, listedAPIKeysAfterExpireByID[idx].GetExpiration().AsTime().Before(time.Now()),
				"Key expired by ID should have expiration in the past")
		}
	}

	// Test delete by ID (using key at index 1)
	deletedKeyID := listedAPIKeysAfterExpireByID[1].GetId()
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"delete",
			"--id",
			strconv.FormatUint(deletedKeyID, 10),
		})
	require.NoError(t, err)

	var listedAPIKeysAfterDeleteByID []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterDeleteByID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after delete by ID")

	assert.Len(t, listedAPIKeysAfterDeleteByID, 3)

	// Verify the specific key was deleted
	for idx := range listedAPIKeysAfterDeleteByID {
		assert.NotEqual(t, deletedKeyID, listedAPIKeysAfterDeleteByID[idx].GetId(),
			"Deleted key should not be present in the list")
	}
}

// TestApiKeyCommandErrors covers the mutually-exclusive --id/--prefix flag
// validation on `apikeys expire` and `apikeys delete`. Both commands must
// reject being given both flags or neither.
func TestApiKeyCommandErrors(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-apikeyerr", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a real key so the server holds data and so a valid prefix exists.
	// `apikeys create` prints the raw secret, not JSON of the key, so list to
	// discover the prefix.
	_, err := headscale.Execute([]string{"headscale", "apikeys", "create", "--output", "json"})
	require.NoError(t, err)

	var listed []v1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "apikeys", "list", "--output", "json"},
			&listed,
		)
		assert.NoError(c, err)
		assert.Len(c, listed, 1)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API key list")

	created := &listed[0]

	for _, sub := range []string{"expire", "delete"} {
		// Neither flag.
		_, err := headscale.Execute([]string{"headscale", "apikeys", sub})
		require.ErrorContains(t, err, "either --id or --prefix must be provided",
			"%s with no selector must error", sub)

		// Both flags.
		_, err = headscale.Execute([]string{
			"headscale", "apikeys", sub,
			"--id", strconv.FormatUint(created.GetId(), 10),
			"--prefix", created.GetPrefix(),
		})
		require.ErrorContains(t, err, "only one of --id or --prefix can be provided",
			"%s with both selectors must error", sub)
	}
}
