package db

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetPolicyKeepsOnlyCurrent checks repeated writes replace the stored
// policy instead of piling up rows.
func TestSetPolicyKeepsOnlyCurrent(t *testing.T) {
	db := dbForTest(t)

	for i := range 5 {
		_, err := db.SetPolicy(
			`{"hosts": {"h": "100.64.0.` + strconv.Itoa(i) + `/32"}}`,
		)
		require.NoError(t, err)
	}

	var rows int64
	require.NoError(t, db.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.Equal(t, int64(1), rows)

	p, err := db.GetPolicy()
	require.NoError(t, err)
	assert.JSONEq(t, `{"hosts": {"h": "100.64.0.4/32"}}`, p.Data)
}

func TestSetPolicyContextDeadlineKeepsCurrent(t *testing.T) {
	database := dbForTest(t)
	initial, err := database.SetPolicy(`{"grants":[]}`)
	require.NoError(t, err)
	pool, err := database.DB.DB()
	require.NoError(t, err)
	conn, err := pool.Conn(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = database.SetPolicyContext(ctx, `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, conn.Close())

	current, err := database.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, initial.ID, current.ID)
	assert.Equal(t, initial.Data, current.Data)

	next, err := database.SetPolicyContext(context.Background(), `{"grants":[]}`)
	require.NoError(t, err)
	assert.Greater(t, next.ID, initial.ID)

	var rows int64
	require.NoError(t, database.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.EqualValues(t, 1, rows)
}
