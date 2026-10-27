package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"probely.com/farcaster/ipnamecache"
)

const (
	defaultTTL = 3600

	defaultAttemptTimeout = 5 * time.Second
	lookupTimeout         = 10 * time.Second
)

type resolver struct {
	// preferred is the starting index in the fixed resolver list.
	preferred atomic.Int64

	// System DNS resolvers.
	resolvers []string

	attemptTimeout time.Duration

	// Cache for our local (non-loopback) IP address.
	localIP     net.IP
	lastIPCheck time.Time

	// Logger.
	log *zap.SugaredLogger

	// Enable IPv6 DNS resolution
	useIPv6 bool

	// IP->hostname cache.
	ipCache *ipnamecache.IPNameCache
}

func newResolver(logger *zap.SugaredLogger, ipv6 bool, ipc *ipnamecache.IPNameCache) (*resolver, error) {
	resolvers, err := getSystemResolvers()
	logger.Infof("System DNS resolvers: %v", resolvers)
	// Add port 53 to resolvers.
	for i, resolver := range resolvers {
		resolvers[i] = net.JoinHostPort(resolver, "53")
	}
	if err != nil {
		return nil, err
	}
	return &resolver{
		resolvers:      resolvers,
		attemptTimeout: defaultAttemptTimeout,
		log:            logger,
		useIPv6:        ipv6,
		ipCache:        ipc,
	}, nil
}

func (r *resolver) Query(qdata []byte, transport string) ([]byte, error) {
	var err error

	// Parse the DNS request.
	query := new(dns.Msg)
	err = query.Unpack(qdata)
	if err != nil {
		return nil, err
	}

	// For now, we just forward the query to the system DNS resolvers.
	resp, err := r.Forward(query, transport)
	if err != nil {
		return nil, err
	}

	var rdata []byte
	rdata, err = resp.Pack()
	if err != nil {
		r.log.Errorf("Failed to pack DNS response: %v\n", err)
		return nil, err
	}

	return rdata, nil
}

func (r *resolver) Forward(query *dns.Msg, transport string) (*dns.Msg, error) {
	if len(query.Question) == 0 {
		return nil, fmt.Errorf("no questions in DNS query")
	}

	question := query.Question[0]

	// If IPv6 is disabled and this is a pure AAAA query, return an empty response
	if !r.useIPv6 && question.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(query)
		// Return success with no answer records
		// This allows clients to fall back to A records without delays
		r.log.Debugf("IPv6 disabled: returning empty response for AAAA query %s", question.Name)
		return resp, nil
	}

	var resp *dns.Msg
	var err error
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		defer cancel()
		resp, err = r.lookupIP(ctx, query)
	} else {
		resp, err = r.exchange(context.Background(), query, transport)
	}

	if err != nil {
		r.log.Warnf("DNS forwarding failed: %v", err)
		resp = new(dns.Msg)
		resp.SetRcode(query, dns.RcodeServerFailure)
	}
	r.log.Debugf("\n-----query-----\n %v\n-----resp-----\n%v\n", query, resp)
	return resp, nil
}

// lookupIP resolves a hostname to an IP address. It uses the system DNS
// resolver.
func (r *resolver) lookupIP(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Helper function to reply with a name error.
	setNXDomain := func(resp *dns.Msg, host string) {
		r.log.Debugf("Failed to resolve hostname: no IP addresses found")
		resp.Rcode = dns.RcodeNameError
		soa, err := r.lookupSOA(ctx, host)
		r.log.Debugf("SOA for failed hostname %s: %v, %v", host, soa, err)
		if err == nil {
			resp.Ns = append(resp.Ns, soa)
		}
	}

	// Resolve the hostname.
	question := query.Question[0]
	host := dns.Fqdn(question.Name)
	// If the hostname has only one dot and ends with a dot, remove the trailing dot.
	// This allows the system resolver to apply search domains.
	if strings.Count(host, ".") == 1 && strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}

	resp := new(dns.Msg)
	resp.SetReply(query)

	// Use "ip4" network type when IPv6 is disabled to avoid AAAA queries to upstream resolvers
	network := "ip"
	if !r.useIPv6 {
		network = "ip4"
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		// Handle NXDOMAIN errors.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			r.log.Debugf("Failed to resolve hostname (DNS) %s: %v", host, dnsErr)
			setNXDomain(resp, host)
			return resp, nil
		}
		// Otherwise, return SERVFAIL.
		r.log.Debugf("Failed to resolve hostname (DNS) %s: %v", host, err)
		resp.Rcode = dns.RcodeServerFailure
		return resp, nil
	}

	// Add the resolved IP addresses to the response.
	for _, ip := range ips {
		r.log.Debugf("Resolved hostname: %v -> %v", host, ip)
		var rr dns.RR

		if question.Qtype == dns.TypeA && ip.To4() != nil {
			if ip.Equal(net.IPv4(127, 0, 0, 1)) &&
				os.Getenv("FARCASTER_OVERRIDE_LOOPBACK") != "" {
				// If the IP is 127.0.0.1 replace it with the default interface IP.
				ip = r.overrideLoopbackIPv4()
			}
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				A: ip,
			}
		} else if question.Qtype == dns.TypeAAAA && ip.To4() == nil {
			// Skip IPv6 addresses if IPv6 is disabled.
			if !r.useIPv6 {
				continue
			}
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				AAAA: ip,
			}
		} else {
			continue
		}
		r.log.Debugf("Appending RR to answer: %s -> %v", host, rr)
		resp.Answer = append(resp.Answer, rr)
	}

	// Update the IP->hostname cache (A records only).
	if r.ipCache != nil && question.Qtype == dns.TypeA {
		// Convert []net.IP to []netip.Addr
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) > 0 {
			r.ipCache.Update(host, addrs)
		}
	}

	// If we didn't find any IP, return a name error.
	if len(ips) == 0 {
		setNXDomain(resp, host)
	}

	return resp, nil
}

// exchange starts with the last resolver to return NOERROR or NXDOMAIN, then
// cycles through the others after transport errors or SERVFAIL, REFUSED and
// NOTIMP replies. Each resolver gets one attempt of up to attemptTimeout.
// If all attempts fail, it returns the last failure reply, or an error if
// none replied.
//
// A preferred resolver's NXDOMAIN can hide split-DNS names that another
// resolver could answer. Use resolvers with a consistent view of the DNS
// namespace.
func (r *resolver) exchange(ctx context.Context, query *dns.Msg, transport string) (*dns.Msg, error) {
	if transport != "udp" && transport != "tcp" {
		return nil, fmt.Errorf("invalid transport: %s", transport)
	}
	if len(r.resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	client := &dns.Client{Net: transport, Timeout: r.attemptTimeout}
	var lastResp *dns.Msg
	var lastErr error
	start := int(r.preferred.Load())
	for offset := range r.resolvers {
		index := (start + offset) % len(r.resolvers)
		address := r.resolvers[index]
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		attemptCtx, cancel := context.WithTimeout(ctx, r.attemptTimeout)
		resp, err := exchangeWithResolver(attemptCtx, client, query, address)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("resolver %s: %w", address, err)
			r.log.Debugf("DNS upstream failed: %v", lastErr)
			continue
		}
		switch resp.Rcode {
		case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented:
			lastResp = resp
			continue
		case dns.RcodeSuccess, dns.RcodeNameError:
			r.preferred.Store(int64(index))
		}
		return resp, nil
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, fmt.Errorf("all resolvers failed: %w", lastErr)
}

// exchangeWithResolver closes the DNS socket when ctx is canceled.
func exchangeWithResolver(ctx context.Context, client *dns.Client, query *dns.Msg, address string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	resp, _, err := client.ExchangeWithConnContext(ctx, query, conn)
	return resp, err
}

// lookupSOA queries the configured resolvers for the SOA record of the given host.
func (r *resolver) lookupSOA(ctx context.Context, host string) (dns.RR, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), dns.TypeSOA)
	query.RecursionDesired = true

	resp, err := r.exchange(ctx, query, "udp")
	if err != nil || len(resp.Ns) == 0 {
		if err == nil {
			err = fmt.Errorf("no SOA records found")
		}
		r.log.Debugf("Failed to resolve SOA: %v", err)
		return nil, err
	}

	return resp.Ns[0], nil
}

func (r *resolver) overrideLoopbackIPv4() net.IP {
	// Check if the cache for our own IP address is up to date.
	if time.Since(r.lastIPCheck) > defaultTTL*time.Second {
		r.lastIPCheck = time.Now()

		// Get the IP address of the default interface.
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			r.log.Errorf("Failed to get interface addresses: %v", err)
			return net.IPv4(127, 0, 0, 1) // fallback
		}

		// Use the first non-loopback IP address we find.
		r.localIP = nil // reset before scanning
		for _, addr := range addrs {
			r.log.Debugf("Checking address: %v", addr)

			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				r.localIP = ip
				// Prefer RFC1918 addresses.
				if ip.IsPrivate() {
					break
				}
			}
		}

		if r.localIP == nil {
			r.log.Warn("No non-loopback IPv4 address found; falling back to 127.0.0.1")
		}
	}

	if r.localIP != nil {
		return r.localIP
	}
	return net.IPv4(127, 0, 0, 1)
}
