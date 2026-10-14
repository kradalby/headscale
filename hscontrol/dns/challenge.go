package dns

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
)

var (
	ErrTooManyChallenges = errors.New("too many pending ACME challenges for this name")
	ErrChallengeProvider = errors.New("DNS provider failed")
	ErrEmptyChallenge    = errors.New("empty ACME challenge value")
)

const (
	challengeTTL = time.Minute
	// challengeLifetime outlives both authorizations of a wildcard order
	// and the CA's validation retries. A retry of the same order resends
	// the same value, which restarts the clock.
	challengeLifetime = 10 * time.Minute
	// maxChallengesPerName covers a wildcard order (two values) racing a
	// plain order for the same name. It also bounds how many records one
	// node can make headscale write.
	maxChallengesPerName = 4
	providerTimeout      = 30 * time.Second
	// caLookupDelay is how long after Present returns the CA may still
	// make its first lookup of the value.
	caLookupDelay = 5 * time.Second
)

// Challenges publishes ACME DNS-01 TXT values through a [Provider] and
// removes them again. Clients never ask for removal, so every value is
// deleted [challengeLifetime] after it was last published or on
// [Challenges.Close]. Nothing is persisted: a crash, or a failed delete,
// leaves a few random TXT values behind.
type Challenges struct {
	provider Provider
	zone     string
	lifetime time.Duration
	wait     func(ctx context.Context, zone, fqdn, value string) error

	mu    sync.Mutex
	names map[string]*challengeName
}

type challengeName struct {
	// mu serialises provider calls for one name, so values of one
	// wildcard order cannot overwrite each other in providers that
	// read-modify-write a record set.
	mu     sync.Mutex
	fqdn   string
	values map[string]*challengeValue
	// waiting counts Present calls waiting for propagation, so duplicate
	// requests cannot pile up DNS queries.
	waiting int
	// shownAt is when Present returned, or will return, for shownValue.
	shownAt    time.Time
	shownValue string
}

type challengeValue struct {
	// record is what the provider returned from AppendRecords; deleting
	// exactly it matters for providers that match on TTL or record ID.
	record libdns.Record
	timer  *time.Timer
}

// NewChallenges returns a [Challenges] writing into zone. Present waits up
// to propagationTimeout for the zone's nameservers, found through
// resolvers, to serve a value.
func NewChallenges(
	provider Provider,
	zone string,
	resolvers []string,
	propagationTimeout time.Duration,
) *Challenges {
	return &Challenges{
		provider: provider,
		zone:     fqdn(zone),
		lifetime: challengeLifetime,
		wait:     newTXTChecker(resolvers, propagationTimeout).wait,
		names:    make(map[string]*challengeName),
	}
}

// Present publishes value as a TXT record at name and returns once the
// zone's nameservers serve it. Values are added next to existing ones,
// never replacing them, and publishing a value again is a no-op.
func (c *Challenges) Present(ctx context.Context, name, value string) error {
	if value == "" {
		return ErrEmptyChallenge
	}

	n := c.name(fqdn(name))

	err := c.append(ctx, n, value)
	if err != nil {
		return err
	}

	err = c.wait(ctx, c.zone, n.fqdn, value)
	if err == nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(time.Until(n.show(value))):
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.waiting--

	// A failed wait keeps the value until its lifetime ends: deleting it
	// at once would let a client that cancels requests in a loop make
	// headscale call the provider without bound. A success restarts the
	// lifetime, which is the CA's window to validate.
	if v, ok := n.values[value]; ok && err == nil {
		v.timer.Reset(c.lifetime)
	}

	return err
}

// append publishes value unless it already is, and counts the caller as
// waiting.
func (c *Challenges) append(ctx context.Context, n *challengeName, value string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.waiting >= maxChallengesPerName {
		return ErrTooManyChallenges
	}

	if v, ok := n.values[value]; ok {
		v.timer.Reset(c.lifetime)

		n.waiting++

		return nil
	}

	if len(n.values) >= maxChallengesPerName {
		return ErrTooManyChallenges
	}

	record := libdns.TXT{
		Name: libdns.RelativeName(n.fqdn, c.zone),
		TTL:  challengeTTL,
		Text: value,
	}

	// The call must finish even if the client goes away, or a record
	// could be created that nothing tracks and deletes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerTimeout)
	defer cancel()

	got, err := c.provider.AppendRecords(ctx, c.zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrChallengeProvider, err)
	}

	stored := libdns.Record(record)
	if len(got) == 1 && got[0].RR().Type == "TXT" && got[0].RR().Data == value {
		stored = got[0]
	}

	n.values[value] = &challengeValue{
		record: stored,
		timer:  time.AfterFunc(c.lifetime, func() { c.remove(n, value) }), //nolint:contextcheck // outlives the request
	}
	n.waiting++

	return nil
}

// show reserves when Present may return for value. The client asks the
// CA to validate at once, and the CA's resolvers cache the record set they
// find for its TTL. A resolver that cached this name for an earlier value,
// such as the first of a wildcard order, would not see a new one, so a
// new value is held back until that cache has expired.
func (n *challengeName) show(value string) time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()

	at := time.Now()
	if expired := n.shownAt.Add(challengeTTL + caLookupDelay); value != n.shownValue && expired.After(at) {
		at = expired
	}

	n.shownAt, n.shownValue = at, value

	return at
}

// remove deletes one tracked value from the provider. It never deletes by
// name alone: providers treat an empty value as "every record here",
// which would take out the operator's records and the other value of a
// wildcard order.
func (c *Challenges) remove(n *challengeName, value string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	v, ok := n.values[value]
	if !ok {
		return
	}

	v.timer.Stop()
	delete(n.values, value)

	ctx, cancel := context.WithTimeout(context.Background(), providerTimeout)
	defer cancel()

	_, err := c.provider.DeleteRecords(ctx, c.zone, []libdns.Record{v.record})
	if err != nil {
		log.Warn().Err(err).Str("fqdn", n.fqdn).Msg("removing ACME challenge record")
	}
}

// name returns the tracking entry for fqdn. Entries are never dropped, so
// a timer always finds the entry it was created for; there is at most one
// per node name.
func (c *Challenges) name(fqdn string) *challengeName {
	c.mu.Lock()
	defer c.mu.Unlock()

	n, ok := c.names[fqdn]
	if !ok {
		n = &challengeName{fqdn: fqdn, values: make(map[string]*challengeValue)}
		c.names[fqdn] = n
	}

	return n
}

// Close deletes every pending value.
func (c *Challenges) Close() {
	c.mu.Lock()
	names := slices.Collect(maps.Values(c.names))
	c.mu.Unlock()

	for _, n := range names {
		n.mu.Lock()
		values := slices.Collect(maps.Keys(n.values))
		n.mu.Unlock()

		for _, value := range values {
			c.remove(n, value)
		}
	}
}

func fqdn(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}
