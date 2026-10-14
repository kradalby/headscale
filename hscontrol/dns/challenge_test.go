package dns

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testZone = "ts.example.com."
	testName = "_acme-challenge.node.ts.example.com."
	// operatorValue is a record headscale did not create and must keep.
	operatorValue = "operator-owned"
)

var (
	errSlow    = errors.New("slow nameserver")
	errAPIDown = errors.New("api down")
)

func newTestChallenges(p *dnstest.Provider) *Challenges {
	c := NewChallenges(p, "TS.example.com", nil, 0)
	c.wait = func(context.Context, string, string, string) error { return nil }

	return c
}

func TestChallengesAppendNotReplace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		p.Add(testName, operatorValue)
		c := newTestChallenges(p)
		ctx := context.Background()

		// A wildcard order sends two values for one name, one after the other.
		require.NoError(t, c.Present(ctx, testName, "value-1"))
		require.NoError(t, c.Present(ctx, "_acme-challenge.NODE.ts.example.com", "value-2"))
		assert.ElementsMatch(t, []string{operatorValue, "value-1", "value-2"}, p.Values(testName))

		// A retry of the same order resends the same value.
		require.NoError(t, c.Present(ctx, testName, "value-1"))
		assert.Len(t, p.Calls(), 2, "resent value must not be appended again")

		for _, call := range p.Calls() {
			assert.Equal(t, testZone, call.Zone)
		}

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()

		assert.Equal(t, []string{operatorValue}, p.Values(testName))
	})
}

func TestChallengesResendExtendsLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		ctx := context.Background()

		require.NoError(t, c.Present(ctx, testName, "value"))
		time.Sleep(challengeLifetime - time.Minute) //nolint:forbidigo // synctest fake clock
		require.NoError(t, c.Present(ctx, testName, "value"))
		time.Sleep(2 * time.Minute) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Equal(t, []string{"value"}, p.Values(testName))

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Empty(t, p.Values(testName))
	})
}

func TestChallengesLimitPerName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		ctx := context.Background()

		for i := range maxChallengesPerName {
			require.NoError(t, c.Present(ctx, testName, "value-"+string(rune('a'+i))))
		}

		err := c.Present(ctx, testName, "one-too-many")
		require.ErrorIs(t, err, ErrTooManyChallenges)
		assert.Len(t, p.Calls(), maxChallengesPerName)

		// Other names have their own limit.
		require.NoError(t, c.Present(ctx, "_acme-challenge.other.ts.example.com", "value"))

		c.Close()
	})
}

// TestChallengesHoldsNewValueForCACache pins that a second value on a name
// is answered only once the CA's cache of the first has expired: the CA
// validates the second value of a wildcard order seconds after the first.
func TestChallengesHoldsNewValueForCACache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestChallenges(&dnstest.Provider{})
		ctx := context.Background()
		start := time.Now()

		require.NoError(t, c.Present(ctx, testName, "value-1"))
		assert.Equal(t, start, time.Now(), "first value is not held")

		require.NoError(t, c.Present(ctx, "_acme-challenge.other.ts.example.com", "value-2"))
		assert.Equal(t, start, time.Now(), "other names are not held")

		require.NoError(t, c.Present(ctx, testName, "value-2"))
		assert.Equal(t, start.Add(challengeTTL+caLookupDelay), time.Now())

		shown := time.Now()

		require.NoError(t, c.Present(ctx, testName, "value-2"))
		assert.Equal(t, shown, time.Now(), "a resent value is not held")

		ctx, cancel := context.WithCancel(ctx)
		cancel()
		require.ErrorIs(t, c.Present(ctx, testName, "value-3"), context.Canceled)

		c.Close()
	})
}

// TestChallengesFailedWaitKeepsValue pins that a failed or cancelled wait
// leaves the value for its lifetime: deleting at once would let a client
// that cancels in a loop drive unbounded provider calls.
func TestChallengesFailedWaitKeepsValue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		c.wait = func(context.Context, string, string, string) error { return errSlow }

		require.ErrorIs(t, c.Present(context.Background(), testName, "value"), errSlow)
		assert.Equal(t, []string{"value"}, p.Values(testName))

		// A retry of the same value is not appended again.
		c.wait = func(context.Context, string, string, string) error { return nil }
		require.NoError(t, c.Present(context.Background(), testName, "value"))
		assert.Len(t, p.Calls(), 1)

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Empty(t, p.Values(testName))
	})
}

// TestChallengesLimitsWaiters pins that duplicate requests for one name
// cannot pile up propagation waits.
func TestChallengesLimitsWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)

		release := make(chan struct{})
		c.wait = func(context.Context, string, string, string) error {
			<-release

			return nil
		}

		for range maxChallengesPerName {
			go func() { _ = c.Present(context.Background(), testName, "value") }()
		}

		synctest.Wait()
		require.ErrorIs(t, c.Present(context.Background(), testName, "value"), ErrTooManyChallenges)

		close(release)
		synctest.Wait()

		c.wait = func(context.Context, string, string, string) error { return nil }
		require.NoError(t, c.Present(context.Background(), testName, "value"))
		c.Close()
	})
}

func TestChallengesProviderError(t *testing.T) {
	p := &dnstest.Provider{}
	p.SetError(errAPIDown)
	c := newTestChallenges(p)

	err := c.Present(context.Background(), testName, "value")
	require.ErrorIs(t, err, ErrChallengeProvider)

	p.SetError(nil)
	c.Close()
	assert.Len(t, p.Calls(), 1, "failed append must not be tracked for deletion")
}

func TestChallengesClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		p.Add(testName, operatorValue)
		c := newTestChallenges(p)
		ctx := context.Background()

		require.NoError(t, c.Present(ctx, testName, "value-1"))
		require.NoError(t, c.Present(ctx, testName, "value-2"))
		c.Close()

		assert.Equal(t, []string{operatorValue}, p.Values(testName))

		for _, call := range p.Calls() {
			assert.NotEmpty(t, call.Value, "a delete without value wipes the record set")
		}
	})
}

func TestChallengesEmptyValue(t *testing.T) {
	p := &dnstest.Provider{}
	c := newTestChallenges(p)

	require.ErrorIs(t, c.Present(context.Background(), testName, ""), ErrEmptyChallenge)
	assert.Empty(t, p.Calls())
}

func TestChallengesClientGoneStillTracks(t *testing.T) {
	p := &dnstest.Provider{}
	c := newTestChallenges(p)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c.wait = func(ctx context.Context, _, _, _ string) error { return ctx.Err() }

	err := c.Present(ctx, testName, "value")
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"value"}, p.Values(testName), "append must finish for a gone client")

	c.Close()
	assert.Empty(t, p.Values(testName), "value appended for a gone client must still be removed")
}
