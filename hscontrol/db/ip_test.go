package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
)

var mpp = func(pref string) *netip.Prefix {
	p := netip.MustParsePrefix(pref)
	return &p
}

var na = netip.MustParseAddr

var nap = func(pref string) *netip.Addr {
	n := na(pref)
	return &n
}

func TestIPAllocatorSequential(t *testing.T) {
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		prefix4  *netip.Prefix
		prefix6  *netip.Prefix
		getCount int
		want4    []netip.Addr
		want6    []netip.Addr
	}{
		{
			name: "simple",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.1"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
			},
		},
		{
			name: "simple-v4",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.1"),
			},
		},
		{
			name: "simple-v6",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
			},
		},
		{
			name: "simple-with-db",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.2"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::2"),
			},
		},
		{
			name: "before-after-free-middle-in-db",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.2"),
					IPv6: nap("fd7a:115c:a1e0::2"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 2,

			want4: []netip.Addr{
				na("100.64.0.1"),
				na("100.64.0.3"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
				na("fd7a:115c:a1e0::3"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, _ := NewIPAllocator(
				db,
				tt.prefix4,
				tt.prefix6,
				types.IPAllocationStrategySequential,
			)

			var (
				got4s []netip.Addr
				got6s []netip.Addr
			)

			for range tt.getCount {
				got4, got6, err := alloc.Next()
				if err != nil {
					t.Fatalf("allocating next IP: %s", err)
				}

				if got4 != nil {
					got4s = append(got4s, *got4)
				}

				if got6 != nil {
					got6s = append(got6s, *got6)
				}
			}

			if diff := cmp.Diff(tt.want4, got4s, util.Comparers...); diff != "" {
				t.Errorf("IPAllocator 4s unexpected result (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.want6, got6s, util.Comparers...); diff != "" {
				t.Errorf("IPAllocator 6s unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPAllocatorRandom(t *testing.T) {
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		getCount int

		prefix4 *netip.Prefix
		prefix6 *netip.Prefix
		want4   bool
		want6   bool
	}{
		{
			name: "simple",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: true,
			want6: true,
		},
		{
			name: "simple-v4",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),

			getCount: 1,

			want4: true,
			want6: false,
		},
		{
			name: "simple-v6",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: false,
			want6: true,
		},
		{
			name: "generate-lots-of-random",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1000,

			want4: true,
			want6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, _ := NewIPAllocator(db, tt.prefix4, tt.prefix6, types.IPAllocationStrategyRandom)

			for range tt.getCount {
				got4, got6, err := alloc.Next()
				if err != nil {
					t.Fatalf("allocating next IP: %s", err)
				}

				t.Logf("addrs ipv4: %v, ipv6: %v", got4, got6)

				if tt.want4 {
					if got4 == nil {
						t.Fatalf("expected ipv4 addr, got nil")
					}
				}

				if tt.want6 {
					if got6 == nil {
						t.Fatalf("expected ipv4 addr, got nil")
					}
				}
			}
		})
	}
}

func TestBackfillIPAddresses(t *testing.T) {
	fullNodeP := func(i int) *types.Node {
		v4 := fmt.Sprintf("100.64.0.%d", i)
		v6 := fmt.Sprintf("fd7a:115c:a1e0::%d", i)

		return &types.Node{
			IPv4: nap(v4),
			IPv6: nap(v6),
		}
	}
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		prefix4 *netip.Prefix
		prefix6 *netip.Prefix
		want    types.Nodes
	}{
		{
			name: "simple-backfill-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "simple-backfill-ipv4",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "simple-backfill-remove-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
				},
			},
		},
		{
			name: "simple-backfill-remove-ipv4",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "multi-backfill-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.2"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.3"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.4"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				fullNodeP(1),
				fullNodeP(2),
				fullNodeP(3),
				fullNodeP(4),
			},
		},
	}

	comps := append(util.Comparers, cmpopts.IgnoreFields(types.Node{},
		"ID",
		"User",
		"UserID",
		"Endpoints",
		"Hostinfo",
		"CreatedAt",
		"UpdatedAt",
	))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, err := NewIPAllocator(
				db,
				tt.prefix4,
				tt.prefix6,
				types.IPAllocationStrategySequential,
			)
			if err != nil {
				t.Fatalf("failed to set up ip alloc: %s", err)
			}

			logs, err := db.BackfillNodeIPs(alloc)
			if err != nil {
				t.Fatalf("failed to backfill: %s", err)
			}

			t.Logf("backfill log: \n%s", strings.Join(logs, "\n"))

			got, err := db.ListNodes()
			if err != nil {
				t.Fatalf("failed to get nodes: %s", err)
			}

			if diff := cmp.Diff(tt.want, got, comps...); diff != "" {
				t.Errorf("Backfill unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPAllocatorNextNoReservedIPs(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	defer db.Close()

	alloc, err := NewIPAllocator(
		db,
		new(tsaddr.CGNATRange()),
		new(tsaddr.TailscaleULARange()),
		types.IPAllocationStrategySequential,
	)
	if err != nil {
		t.Fatalf("failed to set up ip alloc: %s", err)
	}

	// Validate that we do not give out 100.100.100.100
	nextQuad100, err := alloc.next(na("100.100.100.99"), new(tsaddr.CGNATRange()))
	require.NoError(t, err)
	assert.Equal(t, na("100.100.100.101"), *nextQuad100)

	// Validate that we do not give out fd7a:115c:a1e0::53
	nextQuad100v6, err := alloc.next(na("fd7a:115c:a1e0::52"), new(tsaddr.TailscaleULARange()))
	require.NoError(t, err)
	assert.Equal(t, na("fd7a:115c:a1e0::54"), *nextQuad100v6)

	// Validate that we do not give out fd7a:115c:a1e0::53
	nextChrome, err := alloc.next(na("100.115.91.255"), new(tsaddr.CGNATRange()))
	t.Logf("chrome: %s", nextChrome.String())
	require.NoError(t, err)
	assert.Equal(t, na("100.115.94.0"), *nextChrome)
}

// Frozen pre-optimization allocator; only identifiers are renamed. Keep this
// independent of the production allocator for exact traces and whole-operation benchmarks.
// referenceIPAllocator is a singleton responsible for allocating
// IP addresses for nodes and making sure the same
// address is not handed out twice. There can only be one
// and it needs to be created before any other database
// writes occur.
type referenceIPAllocator struct {
	mu sync.Mutex

	prefix4 *netip.Prefix
	prefix6 *netip.Prefix

	// Previous IPs handed out
	prev4 netip.Addr
	prev6 netip.Addr

	// strategy used for handing out IP addresses.
	strategy types.IPAllocationStrategy

	// Set of all IPs handed out.
	// This might not be in sync with the database,
	// but it is more conservative. If saves to the
	// database fails, the IP will be allocated here
	// until the next restart of Headscale.
	usedIPs netipx.IPSetBuilder
}

// newReferenceIPAllocator returns a new [referenceIPAllocator] singleton which
// can be used to hand out unique IP addresses within the
// provided IPv4 and IPv6 prefix. It needs to be created
// when headscale starts and needs to finish its read
// transaction before any writes to the database occur.
func newReferenceIPAllocator(
	db *HSDatabase,
	prefix4, prefix6 *netip.Prefix,
	strategy types.IPAllocationStrategy,
) (*referenceIPAllocator, error) {
	ret := referenceIPAllocator{
		prefix4: prefix4,
		prefix6: prefix6,

		strategy: strategy,
	}

	var (
		v4s []sql.NullString
		v6s []sql.NullString
	)

	if db != nil {
		err := db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv4", &v4s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv4 addresses from database: %w", err)
		}

		err = db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv6", &v6s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv6 addresses from database: %w", err)
		}
	}

	var ips netipx.IPSetBuilder

	// Add network and broadcast addrs to used pool so they
	// are not handed out to nodes.
	if prefix4 != nil {
		network4, broadcast4 := util.GetIPPrefixEndpoints(*prefix4)
		ips.Add(network4)
		ips.Add(broadcast4)

		// Use network as starting point, it will be used to call .Next()
		// TODO(kradalby): Could potentially take all the IPs loaded from
		// the database into account to start at a more "educated" location.
		ret.prev4 = network4
	}

	if prefix6 != nil {
		network6, broadcast6 := util.GetIPPrefixEndpoints(*prefix6)
		ips.Add(network6)
		ips.Add(broadcast6)

		ret.prev6 = network6
	}

	// Fetch all the IP Addresses currently handed out from the Database
	// and add them to the used IP set.
	for _, addrStr := range append(v4s, v6s...) {
		if addrStr.Valid {
			addr, err := netip.ParseAddr(addrStr.String)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address from database: %w", err)
			}

			ips.Add(addr)
		}
	}

	// Build the initial IPSet to validate that we can use it.
	_, err := ips.IPSet()
	if err != nil {
		return nil, fmt.Errorf(
			"building initial IP Set: %w",
			err,
		)
	}

	ret.usedIPs = ips

	return &ret, nil
}

func (i *referenceIPAllocator) Next() (*netip.Addr, *netip.Addr, error) {
	var (
		err  error
		ret4 *netip.Addr
		ret6 *netip.Addr
	)

	if i.prefix4 != nil {
		ret4, err = i.allocateNext(&i.prev4, i.prefix4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}
	}

	if i.prefix6 != nil {
		ret6, err = i.allocateNext(&i.prev6, i.prefix6)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}
	}

	return ret4, ret6, nil
}

// allocateNext allocates the next address from prefix under i.mu, advancing
// prev so a run of allocations (e.g. referenceBackfillNodeIPs) does not rescan
// already-issued addresses, and so prev is read under the lock rather than in
// the caller's frame.
func (i *referenceIPAllocator) allocateNext(prev *netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	ret, err := i.next(*prev, prefix)
	if err != nil {
		return nil, err
	}

	*prev = *ret

	return ret, nil
}

func (i *referenceIPAllocator) next(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	var (
		err error
		ip  netip.Addr
	)

	switch i.strategy {
	case types.IPAllocationStrategySequential:
		// Get the first IP in our prefix
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = referenceRandomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}

	// TODO(kradalby): maybe this can be done less often.
	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	// Walk forward from the starting address until a free, non-reserved
	// address inside the prefix is found. The random strategy only picks the
	// starting point at random and then scans deterministically: this keeps
	// the loop finite, so an exhausted prefix returns ErrCouldNotAllocateIP
	// instead of re-drawing in-prefix addresses forever under i.mu.
	start := ip
	for {
		if prefix.Contains(ip) && !set.Contains(ip) && !referenceIsTailscaleReservedIP(ip) {
			i.usedIPs.Add(ip)

			return &ip, nil
		}

		ip = ip.Next()

		switch i.strategy {
		case types.IPAllocationStrategySequential:
			// Sequential allocation never wraps: walking past the end of
			// the prefix means the pool is exhausted.
			if !prefix.Contains(ip) {
				return nil, ErrCouldNotAllocateIP
			}
		case types.IPAllocationStrategyRandom:
			// Random allocation wraps within the prefix so every address is
			// examined exactly once; returning to the start means the prefix
			// is exhausted.
			if !prefix.Contains(ip) {
				ip = prefix.Masked().Addr()
			}

			if ip == start {
				return nil, ErrCouldNotAllocateIP
			}
		}
	}
}

func referenceRandomNext(pfx netip.Prefix) (netip.Addr, error) {
	rang := netipx.RangeOfPrefix(pfx)
	fromIP, toIP := rang.From(), rang.To()

	var from, to big.Int

	from.SetBytes(fromIP.AsSlice())
	to.SetBytes(toIP.AsSlice())

	// Find the max, this is how we can do "random range",
	// get the "max" as 0 -> to - from and then add back from
	// after.
	tempMax := big.NewInt(0).Sub(&to, &from)

	// A single-address prefix (/32 or /128) has from == to, so tempMax is 0 and
	// rand.Int would panic on a non-positive bound. Return the sole address.
	if tempMax.Sign() <= 0 {
		return fromIP, nil
	}

	out, err := rand.Int(rand.Reader, tempMax)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("generating random IP: %w", err)
	}

	valInRange := big.NewInt(0).Add(&from, out)

	// big.Int.Bytes() strips leading zero bytes, so a value with a zero high
	// byte yields a too-short slice that AddrFromSlice rejects. Pad to the
	// prefix's address width.
	ip, ok := netip.AddrFromSlice(valInRange.FillBytes(make([]byte, len(fromIP.AsSlice()))))
	if !ok {
		return netip.Addr{}, errGeneratedIPBytesInvalid
	}

	if !pfx.Contains(ip) {
		return netip.Addr{}, fmt.Errorf(
			"%w: ip(%s) not in prefix(%s)",
			errGeneratedIPNotInPrefix,
			ip.String(),
			pfx.String(),
		)
	}

	return ip, nil
}

func referenceIsTailscaleReservedIP(ip netip.Addr) bool {
	return tsaddr.ChromeOSVMRange().Contains(ip) ||
		tsaddr.TailscaleServiceIP() == ip ||
		tsaddr.TailscaleServiceIPv6() == ip
}

// referenceBackfillNodeIPs will take a database transaction, and
// iterate through all of the current nodes ([types.Node]) in headscale
// and ensure it has IP addresses according to the current
// configuration.
// This means that if both IPv4 and IPv6 is set in the
// config, and some nodes are missing that type of IP,
// it will be added.
// If a prefix type has been removed (IPv4 or IPv6), it
// will remove the IPs in that family from the node.
func (db *HSDatabase) referenceBackfillNodeIPs(i *referenceIPAllocator) ([]string, error) {
	var (
		err error
		ret []string
	)

	err = db.Write(func(tx *gorm.DB) error {
		if i == nil {
			return fmt.Errorf("backfilling IPs: %w", errIPAllocatorNil)
		}

		log.Trace().Caller().Msgf("starting to backfill IPs")

		nodes, err := ListNodes(tx)
		if err != nil {
			return fmt.Errorf("listing nodes to backfill IPs: %w", err)
		}

		for _, node := range nodes {
			log.Trace().Caller().EmbedObject(node).Msg("ip backfill check started because node found in database")

			changed := false
			// IPv4 prefix is set, but node ip is missing, alloc
			if i.prefix4 != nil && node.IPv4 == nil {
				ret4, err := i.allocateNext(&i.prev4, i.prefix4)
				if err != nil {
					return fmt.Errorf("allocating IPv4 for node(%d): %w", node.ID, err)
				}

				node.IPv4 = ret4
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv4 %q to Node(%d) %q", ret4.String(), node.ID, node.Hostname))
			}

			// IPv6 prefix is set, but node ip is missing, alloc
			if i.prefix6 != nil && node.IPv6 == nil {
				ret6, err := i.allocateNext(&i.prev6, i.prefix6)
				if err != nil {
					return fmt.Errorf("allocating IPv6 for node(%d): %w", node.ID, err)
				}

				node.IPv6 = ret6
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv6 %q to Node(%d) %q", ret6.String(), node.ID, node.Hostname))
			}

			// IPv4 prefix is not set, but node has IP, remove
			if i.prefix4 == nil && node.IPv4 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv4 %q from Node(%d) %q", node.IPv4.String(), node.ID, node.Hostname))
				node.IPv4 = nil
				changed = true
			}

			// IPv6 prefix is not set, but node has IP, remove
			if i.prefix6 == nil && node.IPv6 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv6 %q from Node(%d) %q", node.IPv6.String(), node.ID, node.Hostname))
				node.IPv6 = nil
				changed = true
			}

			if changed {
				// Use Updates() with Select() to only update IP fields, avoiding overwriting
				// other fields like Expiry. We need Select() because Updates() alone skips
				// zero values, but we DO want to update IPv4/IPv6 to nil when removing them.
				err := tx.Model(node).Select("ipv4", "ipv6").Updates(node).Error
				if err != nil {
					return fmt.Errorf("saving node(%d) after adding IPs: %w", node.ID, err)
				}
			}
		}

		return nil
	})

	return ret, err
}

func (i *referenceIPAllocator) FreeIPs(ips []netip.Addr) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, ip := range ips {
		i.usedIPs.Remove(ip)
	}
}

// Only the isolated child replaces crypto/rand.Reader; other package tests may
// generate credentials concurrently. Identical readers also pin entropy use.
//
//nolint:gosec // Isolated test subprocess and seeded PRNG generate reproducible traces.
func TestIPAllocatorReferenceTraces(t *testing.T) {
	const childEnv = "HEADSCALE_IP_ALLOCATOR_REFERENCE_CHILD"
	if os.Getenv(childEnv) != "1" {
		cmd := exec.CommandContext(
			t.Context(),
			os.Args[0],
			"-test.run=^TestIPAllocatorReferenceTraces$",
			"-test.v",
		)

		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		t.Logf("%s", output)

		return
	}

	originalReader := rand.Reader

	t.Cleanup(func() { rand.Reader = originalReader })

	for _, strategy := range []types.IPAllocationStrategy{
		types.IPAllocationStrategySequential,
		types.IPAllocationStrategyRandom,
	} {
		for _, fixture := range []struct {
			name   string
			p4, p6 *netip.Prefix
			loaded []netip.Addr
		}{
			{"contiguous", mpp("100.64.0.0/18"), mpp("fd7a:115c:a1e0::/112"), nil},
			{"loaded_contiguous", mpp("100.64.0.0/18"), mpp("fd7a:115c:a1e0::/112"), allocatorFixtureIPs(64, false)},
			{"loaded_sparse", mpp("100.64.0.0/10"), mpp("fd7a:115c:a1e0::/48"), allocatorSparseIPs(64)},
			{"fragmented", mpp("100.64.0.0/24"), mpp("fd7a:115c:a1e0::/120"), allocatorFixtureIPs(64, true)},
			{"tiny", mpp("100.64.0.0/30"), mpp("fd7a:115c:a1e0::/126"), nil},
			{"partial_dual_stack", mpp("100.64.0.0/24"), mpp("fd7a:115c:a1e0::/128"), nil},
			{"v4_only", mpp("100.64.0.0/24"), nil, nil},
			{"v6_only", nil, mpp("fd7a:115c:a1e0::/120"), nil},
			{"no_prefixes", nil, nil, nil},
			{"single_address", mpp("100.64.0.1/32"), mpp("fd7a:115c:a1e0::1/128"), nil},
			{"zones_and_mapped", mpp("100.64.0.4/30"), mpp("fd7a:115c:a1e0::4/126"), []netip.Addr{
				na("100.64.0.5"), na("fd7a:115c:a1e0::5%eth0"), na("::ffff:100.64.0.6"),
			}},
		} {
			t.Run(string(strategy)+"/"+fixture.name, func(t *testing.T) {
				var database *HSDatabase
				if len(fixture.loaded) > 0 {
					database = allocatorFixtureDB(t, fixture.loaded)
				}

				for seed := range int64(8) {
					current, err := NewIPAllocator(
						database,
						fixture.p4,
						fixture.p6,
						strategy,
					)
					require.NoError(t, err)
					reference, err := newReferenceIPAllocator(
						database,
						fixture.p4,
						fixture.p6,
						strategy,
					)
					require.NoError(t, err)

					currentEntropy := newAllocatorEntropy(seed)
					referenceEntropy := newAllocatorEntropy(seed)
					operations := mathrand.New(mathrand.NewSource(seed + 100))

					var allocated []netip.Addr

					for step := range 256 {
						switch operations.Intn(6) {
						case 0:
							if len(allocated) > 0 {
								freed := []netip.Addr{
									allocated[operations.Intn(len(allocated))],
								}
								reference.FreeIPs(freed)
								current.FreeIPs(freed)
							}
						case 1:
							// Invalid frees accumulate and fail the next attempted family only.
							freed := []netip.Addr{{}, na("fd7a:115c:a1e0::5%eth0"), {}}
							reference.FreeIPs(freed)
							current.FreeIPs(freed)
						default:
							if step%31 == 0 {
								currentEntropy.err = io.ErrUnexpectedEOF
								referenceEntropy.err = io.ErrUnexpectedEOF
							}

							rand.Reader = referenceEntropy
							want4, want6, wantErr := reference.Next()
							rand.Reader = currentEntropy
							got4, got6, gotErr := current.Next()
							require.Equal(t, want4, got4, "seed=%d step=%d", seed, step)
							require.Equal(t, want6, got6, "seed=%d step=%d", seed, step)
							assertAllocatorError(t, wantErr, gotErr)
							require.Equal(t, reference.prev4, current.prev4)
							require.Equal(t, reference.prev6, current.prev6)
							require.Equal(
								t,
								referenceEntropy.bytes,
								currentEntropy.bytes,
								"entropy consumption",
							)
							currentEntropy.err, referenceEntropy.err = nil, nil

							if got4 != nil {
								allocated = append(allocated, *got4)
							}

							if got6 != nil {
								allocated = append(allocated, *got6)
							}
						}
					}
				}
			})
		}
	}

	t.Run("freed_boundaries", func(t *testing.T) {
		current, err := NewIPAllocator(
			nil,
			mpp("100.64.0.0/30"),
			nil,
			types.IPAllocationStrategySequential,
		)
		require.NoError(t, err)
		reference, err := newReferenceIPAllocator(
			nil,
			current.prefix4,
			nil,
			current.strategy,
		)
		require.NoError(t, err)

		freed := []netip.Addr{na("100.64.0.0"), na("100.64.0.3")}
		reference.FreeIPs(freed)
		current.FreeIPs(freed)

		want, wantErr := reference.next(na("100.64.0.2"), reference.prefix4)
		got, gotErr := current.next(na("100.64.0.2"), current.prefix4)
		require.Equal(t, nap("100.64.0.3"), got, "FreeIPs also frees prefix endpoints")
		require.Equal(t, want, got)
		assertAllocatorError(t, wantErr, gotErr)
	})

	t.Run("zone_membership", func(t *testing.T) {
		current, err := NewIPAllocator(
			nil,
			nil,
			mpp("fd7a:115c:a1e0::/120"),
			types.IPAllocationStrategySequential,
		)
		require.NoError(t, err)
		reference, err := newReferenceIPAllocator(
			nil,
			nil,
			current.prefix6,
			current.strategy,
		)
		require.NoError(t, err)

		for _, prev := range []netip.Addr{
			na("fd7a:115c:a1e0::4%eth0"), na("fd7a:115c:a1e0::4"),
			na("fd7a:115c:a1e0::4%eth0"),
		} {
			want, wantErr := reference.next(prev, reference.prefix6)
			got, gotErr := current.next(prev, current.prefix6)
			require.Equal(t, want, got)
			assertAllocatorError(t, wantErr, gotErr)
		}

		freed := []netip.Addr{na("fd7a:115c:a1e0::5%another-zone")}
		reference.FreeIPs(freed)
		current.FreeIPs(freed)

		want, wantErr := reference.next(na("fd7a:115c:a1e0::4"), reference.prefix6)
		got, gotErr := current.next(na("fd7a:115c:a1e0::4"), current.prefix6)
		require.Equal(t, nap("fd7a:115c:a1e0::5"), got)
		require.Equal(t, want, got)
		assertAllocatorError(t, wantErr, gotErr)
	})

	t.Run("restart", func(t *testing.T) {
		database := allocatorFixtureDB(t, nil)
		current, err := NewIPAllocator(
			database,
			mpp("100.64.0.0/29"),
			nil,
			types.IPAllocationStrategySequential,
		)
		require.NoError(t, err)
		reference, err := newReferenceIPAllocator(
			database,
			current.prefix4,
			nil,
			current.strategy,
		)
		require.NoError(t, err)

		for index := range 3 {
			want, _, wantErr := reference.Next()
			got, _, gotErr := current.Next()
			require.Equal(t, want, got)
			assertAllocatorError(t, wantErr, gotErr)

			if index != 1 {
				require.NoError(t, database.DB.Create(&types.Node{IPv4: got}).Error)
			}
		}

		current, err = NewIPAllocator(database, current.prefix4, nil, current.strategy)
		require.NoError(t, err)
		reference, err = newReferenceIPAllocator(
			database,
			current.prefix4,
			nil,
			current.strategy,
		)
		require.NoError(t, err)

		want, _, wantErr := reference.Next()
		got, _, gotErr := current.Next()
		require.Equal(
			t,
			nap("100.64.0.2"),
			got,
			"restart releases the allocation that was never persisted",
		)
		require.Equal(t, want, got)
		assertAllocatorError(t, wantErr, gotErr)
	})

	t.Run("constructor_errors", func(t *testing.T) {
		invalid := netip.Prefix{}
		_, wantErr := newReferenceIPAllocator(
			nil,
			&invalid,
			nil,
			types.IPAllocationStrategySequential,
		)
		_, gotErr := NewIPAllocator(
			nil,
			&invalid,
			nil,
			types.IPAllocationStrategySequential,
		)
		require.Error(t, gotErr)
		assertAllocatorError(t, wantErr, gotErr)
		database := allocatorFixtureDB(t, []netip.Addr{na("100.64.0.1")})
		require.NoError(
			t,
			database.DB.Model(&types.Node{}).
				Where("id = ?", 1).
				Update("ipv4", "bad-address").
				Error,
		)
		_, wantErr = newReferenceIPAllocator(
			database,
			mpp("100.64.0.0/24"),
			nil,
			types.IPAllocationStrategySequential,
		)
		_, gotErr = NewIPAllocator(
			database,
			mpp("100.64.0.0/24"),
			nil,
			types.IPAllocationStrategySequential,
		)
		require.Error(t, gotErr)
		assertAllocatorError(t, wantErr, gotErr)
	})

	t.Run("backfill", testIPAllocatorReferenceBackfill)
}

type allocatorEntropy struct {
	source *mathrand.Rand
	bytes  int
	err    error
}

//nolint:gosec // This seeded reader only supplies deterministic test entropy.
func newAllocatorEntropy(seed int64) *allocatorEntropy {
	return &allocatorEntropy{source: mathrand.New(mathrand.NewSource(seed))}
}

func (r *allocatorEntropy) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	n, err := r.source.Read(p)
	r.bytes += n

	return n, err
}

func assertAllocatorError(t *testing.T, want, got error) {
	t.Helper()
	require.Equal(t, fmt.Sprintf("%T", want), fmt.Sprintf("%T", got))

	if want == nil {
		return
	}

	require.Equal(t, allocatorErrorMessage(want), allocatorErrorMessage(got))
	require.Equal(
		t,
		errors.Is(want, ErrCouldNotAllocateIP),
		errors.Is(got, ErrCouldNotAllocateIP),
	)
	require.Equal(
		t,
		errors.Is(want, io.ErrUnexpectedEOF),
		errors.Is(got, io.ErrUnexpectedEOF),
	)
}

var allocatorNetipxStackSuffix = regexp.MustCompile(
	`((?:Add|Remove)\(IP\{\}\)) @ (?:\S+\.go:[1-9][0-9]*(?: |$))+$`,
)

func allocatorErrorMessage(err error) string {
	parts := strings.Split(err.Error(), "; ")
	for index, part := range parts {
		parts[index] = allocatorNetipxStackSuffix.ReplaceAllString(part, "${1}")
	}

	return strings.Join(parts, "; ")
}

//nolint:err113 // Synthetic errors verify that message comparisons remain exact.
func TestAllocatorErrorMessage(t *testing.T) {
	for _, message := range []string{
		`parsing IP address from database: ParseAddr("bad @ left"): unable to parse IP`,
		`parsing IP address from database: ParseAddr("bad @ right"): unable to parse IP`,
		`parsing IP address from database: ParseAddr("bad @ /src/ip.go:12"): unable to parse IP`,
		`Remove(IP{}) @ not-a-source-location`,
		`other error @ /src/ip.go:12`,
	} {
		require.Equal(t, message, allocatorErrorMessage(errors.New(message)))
	}

	left := allocatorErrorMessage(errors.New("bad @ left"))
	right := allocatorErrorMessage(errors.New("bad @ right"))
	require.NotEqual(t, left, right)

	for _, message := range []string{
		"Remove(IP{}) @ /src/old.go:12 /src/trace_test.go:90",
		"Remove(IP{}) @ /src/new.go:34 /src/trace_test.go:91",
	} {
		require.Equal(t, "Remove(IP{})", allocatorErrorMessage(errors.New(message)))
	}

	require.Equal(t, "building initial IP Set: Add(IP{}); Add(IP{})", allocatorErrorMessage(errors.New(
		"building initial IP Set: Add(IP{}) @ /src/old.go:12; Add(IP{}) @ /src/old.go:13",
	)))
}

func allocatorFixtureIPs(count int, fragmented bool) []netip.Addr {
	v4, v6 := na("100.64.0.1"), na("fd7a:115c:a1e0::1")

	ips := make([]netip.Addr, 0, 2*count)
	for range count {
		ips = append(ips, v4, v6)

		v4, v6 = v4.Next(), v6.Next()
		if fragmented {
			v4, v6 = v4.Next(), v6.Next()
		}
	}

	return ips
}

func allocatorFixtureDB(tb testing.TB, ips []netip.Addr) *HSDatabase {
	tb.Helper()
	database, err := NewHeadscaleDatabase(&types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/allocator.db"},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	})
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, database.Close()) })

	database.DB.NowFunc = func() time.Time { return time.Unix(1700000000, 0).UTC() }

	nodes := make(types.Nodes, 0, len(ips))
	for _, ip := range ips {
		node := &types.Node{}
		if ip.Is4() {
			node.IPv4 = new(ip)
		} else {
			node.IPv6 = new(ip)
		}

		nodes = append(nodes, node)
	}

	if len(nodes) > 0 {
		require.NoError(tb, database.DB.CreateInBatches(nodes, 100).Error)
	}

	return database
}

// This gate catches reintroducing whole-set materialization on the default path.
func TestIPAllocatorSequentialAllocationBudget(t *testing.T) {
	current, err := NewIPAllocator(
		nil,
		mpp("100.64.0.0/10"),
		mpp("fd7a:115c:a1e0::/48"),
		types.IPAllocationStrategySequential,
	)
	require.NoError(t, err)
	reference, err := newReferenceIPAllocator(
		nil,
		current.prefix4,
		current.prefix6,
		current.strategy,
	)
	require.NoError(t, err)

	got := testing.AllocsPerRun(
		32,
		func() { _, _, err = current.Next(); require.NoError(t, err) },
	)
	want := testing.AllocsPerRun(
		32,
		func() { _, _, err = reference.Next(); require.NoError(t, err) },
	)
	t.Logf("default sequential Next allocations: reference=%g candidate=%g", want, got)
	require.Less(t, got, want)
}

func testIPAllocatorReferenceBackfill(t *testing.T) {
	for _, strategy := range []types.IPAllocationStrategy{types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom} {
		for _, prefixes := range [][2]*netip.Prefix{
			{mpp("100.64.0.0/24"), mpp("fd7a:115c:a1e0::/120")},
			{mpp("100.64.0.0/24"), mpp("fd7a:115c:a1e0::/128")},
			{mpp("100.64.0.0/24"), nil},
			{nil, mpp("fd7a:115c:a1e0::/120")},
			{nil, nil},
		} {
			name := string(
				strategy,
			) + "/v4=" + fmt.Sprint(
				prefixes[0],
			) + "/v6=" + fmt.Sprint(
				prefixes[1],
			)
			t.Run(name, func(t *testing.T) {
				currentDB := allocatorFixtureDB(
					t,
					[]netip.Addr{na("100.64.0.1"), na("fd7a:115c:a1e0::3")},
				)

				referenceDB := allocatorFixtureDB(
					t,
					[]netip.Addr{na("100.64.0.1"), na("fd7a:115c:a1e0::3")},
				)
				for _, database := range []*HSDatabase{currentDB, referenceDB} {
					user, err := database.CreateUser(
						types.User{Name: "allocation-owner"},
					)
					require.NoError(t, err)

					uid := user.ID
					require.NoError(
						t,
						database.DB.Create(
							&types.Node{UserID: &uid, Hostname: "owned"},
						).Error,
					)
					require.NoError(
						t,
						database.DB.Create(
							&types.Node{
								Tags:     types.Strings{"tag:server"},
								Hostname: "tagged",
							},
						).Error,
					)
				}

				current, err := NewIPAllocator(
					currentDB,
					prefixes[0],
					prefixes[1],
					strategy,
				)
				require.NoError(t, err)
				reference, err := newReferenceIPAllocator(
					referenceDB,
					prefixes[0],
					prefixes[1],
					strategy,
				)
				require.NoError(t, err)

				referenceEntropy, currentEntropy := newAllocatorEntropy(
					42,
				), newAllocatorEntropy(
					42,
				)
				rand.Reader = referenceEntropy
				wantLogs, wantErr := referenceDB.referenceBackfillNodeIPs(reference)
				rand.Reader = currentEntropy
				gotLogs, gotErr := currentDB.BackfillNodeIPs(current)
				require.Equal(t, wantLogs, gotLogs)
				assertAllocatorError(t, wantErr, gotErr)

				wantNodes, err := referenceDB.ListNodes()
				require.NoError(t, err)
				gotNodes, err := currentDB.ListNodes()
				require.NoError(t, err)
				require.Equal(t, wantNodes, gotNodes)
				require.Equal(t, reference.prev4, current.prev4)
				require.Equal(t, reference.prev6, current.prev6)
				require.Equal(t, referenceEntropy.bytes, currentEntropy.bytes)
			})
		}
	}
}

// Benchmark the complete allocation, including entropy, reservation checks,
// cursor advancement and locking. Rebuild outside timing to bound population.
func BenchmarkIPAllocatorNext(b *testing.B) {
	for _, strategy := range []types.IPAllocationStrategy{types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom} {
		for _, pattern := range []string{"contiguous", "fragmented", "sparse"} {
			for _, count := range []int{0, 1000, 10000} {
				b.Run(
					fmt.Sprintf("%s/%s/n=%d", strategy, pattern, count),
					func(b *testing.B) {
						var database *HSDatabase

						if count > 0 {
							ips := allocatorFixtureIPs(count, pattern == "fragmented")
							if pattern == "sparse" {
								ips = allocatorSparseIPs(count)
							}

							database = allocatorFixtureDB(b, ips)
						}

						for _, old := range []bool{true, false} {
							name := "new"
							if old {
								name = "old"
							}

							b.Run(name, func(b *testing.B) {
								b.ReportAllocs()

								for completed := 0; completed < b.N; {
									b.StopTimer()

									var next func() (*netip.Addr, *netip.Addr, error)

									if old {
										allocator, err := newReferenceIPAllocator(
											database,
											mpp("100.64.0.0/10"),
											mpp("fd7a:115c:a1e0::/48"),
											strategy,
										)
										require.NoError(b, err)

										next = allocator.Next
									} else {
										allocator, err := NewIPAllocator(
											database,
											mpp("100.64.0.0/10"),
											mpp("fd7a:115c:a1e0::/48"),
											strategy,
										)
										require.NoError(b, err)

										next = allocator.Next
									}

									batch := min(4096, b.N-completed)
									b.StartTimer()

									for range batch {
										_, _, err := next()
										if err != nil {
											b.Fatal(err)
										}
									}

									completed += batch
								}
							})
						}
					},
				)
			}
		}
	}
}

// Include the transaction, node reads, all allocations, saves and returned logs.
func BenchmarkIPAllocatorBackfill(b *testing.B) {
	for _, strategy := range []types.IPAllocationStrategy{types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom} {
		for _, pattern := range []string{"contiguous", "sparse"} {
			for _, count := range []int{100, 1000} {
				b.Run(
					fmt.Sprintf("%s/%s/n=%d", strategy, pattern, count),
					func(b *testing.B) {
						ips := allocatorFixtureIPs(count, false)
						if pattern == "sparse" {
							ips = allocatorSparseIPs(count)
						}

						database := allocatorFixtureDB(b, ips)

						for _, old := range []bool{true, false} {
							name := "new"
							if old {
								name = "old"
							}

							b.Run(name, func(b *testing.B) {
								b.ReportAllocs()

								for range b.N {
									b.StopTimer()
									require.NoError(
										b,
										database.DB.Exec(
											"UPDATE nodes SET ipv6 = NULL WHERE id % 2 = 1",
										).Error,
									)
									require.NoError(
										b,
										database.DB.Exec(
											"UPDATE nodes SET ipv4 = NULL WHERE id % 2 = 0",
										).Error,
									)

									var backfill func() ([]string, error)

									if old {
										allocator, err := newReferenceIPAllocator(
											database,
											mpp("100.64.0.0/10"),
											mpp("fd7a:115c:a1e0::/48"),
											strategy,
										)
										require.NoError(b, err)

										backfill = func() ([]string, error) { return database.referenceBackfillNodeIPs(allocator) }
									} else {
										allocator, err := NewIPAllocator(
											database,
											mpp("100.64.0.0/10"),
											mpp("fd7a:115c:a1e0::/48"),
											strategy,
										)
										require.NoError(b, err)

										backfill = func() ([]string, error) { return database.BackfillNodeIPs(allocator) }
									}

									b.StartTimer()

									logs, err := backfill()
									if err != nil {
										b.Fatal(err)
									}

									if len(logs) != 2*count {
										b.Fatalf(
											"backfilled %d addresses, want %d",
											len(logs),
											2*count,
										)
									}
								}
							})
						}
					},
				)
			}
		}
	}
}

//nolint:gosec // Fixture offsets are intentionally split into address octets.
func allocatorSparseIPs(count int) []netip.Addr {
	ips := make([]netip.Addr, 0, 2*count)
	for index := range count {
		offset := uint32(index*251 + 1)
		v4 := netip.AddrFrom4(
			[4]byte{100, 64 + byte(offset>>16), byte(offset >> 8), byte(offset)},
		)
		v6Bytes := na("fd7a:115c:a1e0::").As16()
		v6Bytes[12], v6Bytes[13], v6Bytes[14], v6Bytes[15] = byte(
			offset>>24,
		), byte(
			offset>>16,
		), byte(
			offset>>8,
		), byte(
			offset,
		)
		ips = append(ips, v4, netip.AddrFrom16(v6Bytes))
	}

	return ips
}

func TestIPAllocatorConcurrentNextAndFree(t *testing.T) {
	allocator, err := NewIPAllocator(
		nil,
		mpp("100.64.0.0/10"),
		mpp("fd7a:115c:a1e0::/48"),
		types.IPAllocationStrategySequential,
	)
	require.NoError(t, err)

	results := make(chan []netip.Addr, 512)
	errorsCh := make(chan error, 4)

	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 128 {
				v4, v6, err := allocator.Next()
				if err != nil {
					errorsCh <- err
					return
				}

				ips := []netip.Addr{*v4, *v6}
				results <- ips

				allocator.FreeIPs(ips)
			}
		})
	}

	workers.Wait()
	close(results)
	close(errorsCh)

	for err := range errorsCh {
		require.NoError(t, err)
	}

	seen := make(map[netip.Addr]bool)

	for ips := range results {
		for _, ip := range ips {
			require.False(
				t,
				seen[ip],
				"sequential allocation must not repeat an address after free",
			)
			seen[ip] = true
		}
	}

	require.Len(t, seen, 1024)
}

var ipAllocatorLoadBenchmarkResult any

// Include database reads and membership preparation, with an optional first
// allocation to expose the scan after reloading contiguous addresses.
func BenchmarkIPAllocatorLoad(b *testing.B) {
	for _, pattern := range []string{"contiguous", "fragmented", "sparse"} {
		for _, count := range []int{1000, 10000} {
			b.Run(fmt.Sprintf("%s/n=%d", pattern, count), func(b *testing.B) {
				ips := allocatorFixtureIPs(count, pattern == "fragmented")
				if pattern == "sparse" {
					ips = allocatorSparseIPs(count)
				}

				database := allocatorFixtureDB(b, ips)
				p4, p6 := mpp("100.64.0.0/10"), mpp("fd7a:115c:a1e0::/48")

				for _, mode := range []string{"load", "load_first_next"} {
					b.Run(mode, func(b *testing.B) {
						b.Run("old", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								allocator, err := newReferenceIPAllocator(
									database, p4, p6, types.IPAllocationStrategySequential,
								)
								if err != nil {
									b.Fatal(err)
								}

								if allocator == nil {
									b.Fatal("constructor returned no allocator")
								}

								ipAllocatorLoadBenchmarkResult = allocator
								if mode == "load_first_next" {
									_, _, err = allocator.Next()
									if err != nil {
										b.Fatal(err)
									}
								}
							}
						})
						b.Run("new", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								allocator, err := NewIPAllocator(
									database, p4, p6, types.IPAllocationStrategySequential,
								)
								if err != nil {
									b.Fatal(err)
								}

								if allocator == nil {
									b.Fatal("constructor returned no allocator")
								}

								ipAllocatorLoadBenchmarkResult = allocator
								if mode == "load_first_next" {
									_, _, err = allocator.Next()
									if err != nil {
										b.Fatal(err)
									}
								}
							}
						})
					})
				}
			})
		}
	}
}
