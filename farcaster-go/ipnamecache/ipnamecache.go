// Package ipnamecache provides an IP -> hostname LRU cache with sane defaults.
// Keys use netip.Addr, values store the latest hostname and UpdatedAt.
// Concurrency is provided by the underlying LRU; last-write-wins semantics.
package ipnamecache

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	DefaultCapacity = 32768
)

// Entry is the value stored per IP.
type Entry struct {
	Hostname string
}

// Stats are cheap, monotonic counters for quick visibility.
type Stats struct {
	Hits      uint64
	Misses    uint64
	Updated   uint64
	Unchanged uint64
	Evictions uint64
}

// Snapshot returns an atomic copy of the counters.
func (s *Stats) Snapshot() Stats {
	return Stats{
		Hits:      atomic.LoadUint64(&s.Hits),
		Misses:    atomic.LoadUint64(&s.Misses),
		Updated:   atomic.LoadUint64(&s.Updated),
		Unchanged: atomic.LoadUint64(&s.Unchanged),
		Evictions: atomic.LoadUint64(&s.Evictions),
	}
}

// Normalizer lowercases hostnames by default.
type Normalizer func(string) string

// Options for IPNameCache.
type Options struct {
	Capacity  int        // max entries (default DefaultCapacity)
	Normalize Normalizer // default: strings.ToLower
}

// WithCapacity sets the LRU capacity.
func WithCapacity(n int) func(*Options) { return func(o *Options) { o.Capacity = n } }

// WithNormalizer sets a custom hostname normalizer (e.g. IDNA).
func WithNormalizer(n Normalizer) func(*Options) { return func(o *Options) { o.Normalize = n } }

// IPNameCache maps IP -> latest hostname using an LRU with sane defaults.
// Concurrency is handled by the underlying LRU; no extra locks needed.
type IPNameCache struct {
	lru   *lru.Cache[netip.Addr, Entry]
	opts  Options
	stats Stats
}

// New creates a cache with sane defaults.
func New(opts ...func(*Options)) (*IPNameCache, error) {
	cfg := Options{
		Capacity:  DefaultCapacity,
		Normalize: strings.ToLower,
	}
	for _, f := range opts {
		f(&cfg)
	}
	if cfg.Capacity <= 0 {
		cfg.Capacity = DefaultCapacity
	}

	var ipc IPNameCache
	cache, err := lru.NewWithEvict(cfg.Capacity, func(_ netip.Addr, _ Entry) {
		atomic.AddUint64(&ipc.stats.Evictions, 1)
	})
	if err != nil {
		return nil, err
	}

	ipc.lru = cache
	ipc.opts = cfg
	return &ipc, nil
}

// Get returns hostname for IP if present.
func (c *IPNameCache) Get(ip netip.Addr) (string, bool) {
	if e, ok := c.lru.Get(ip); ok {
		atomic.AddUint64(&c.stats.Hits, 1)
		return e.Hostname, true
	}
	atomic.AddUint64(&c.stats.Misses, 1)
	return "", false
}

// UpdateOne applies compare-before-write semantics: only writes when different or absent.
// Returns true if a write occurred.
func (c *IPNameCache) UpdateOne(ip netip.Addr, hostname string) bool {
	if !ip.IsValid() {
		return false
	}
	host := c.opts.Normalize(hostname)

	if cur, ok := c.lru.Get(ip); ok && cur.Hostname == host {
		atomic.AddUint64(&c.stats.Unchanged, 1)
		return false
	}
	c.lru.Add(ip, Entry{Hostname: host})
	atomic.AddUint64(&c.stats.Updated, 1)
	return true
}

// Update updates the cache from a single resolution result.
func (c *IPNameCache) Update(hostname string, ips []netip.Addr) int {
	if len(ips) == 0 {
		return 0
	}
	// Optional dedupe using a set to avoid x/exp dependency.
	seen := make(map[netip.Addr]struct{}, len(ips))
	dedup := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		dedup = append(dedup, ip)
	}
	updated := 0
	for _, ip := range dedup {
		if c.UpdateOne(ip, hostname) {
			updated++
		}
	}
	return updated
}

// UpdateFromNetIP is a convenience if your resolver returns []net.IP.
func (c *IPNameCache) UpdateFromNetIP(hostname string, ips []net.IP) int {
	if len(ips) == 0 {
		return 0
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, a)
		}
	}
	return c.Update(hostname, addrs)
}

// Len returns the number of entries currently stored.
func (c *IPNameCache) Len() int { return c.lru.Len() }

// Capacity returns the configured max entries.
func (c *IPNameCache) Capacity() int { return c.opts.Capacity }

// Stats returns a snapshot copy of counters.
func (c *IPNameCache) Stats() Stats { return c.stats.Snapshot() }

// Purge clears the cache.
func (c *IPNameCache) Purge() { c.lru.Purge() }
