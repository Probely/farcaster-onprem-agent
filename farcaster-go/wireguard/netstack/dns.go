package netstack

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	defaultTTL = 3600

	resolverDelay = 500 * time.Millisecond
	queryTimeout  = 10 * time.Second
)

type resolver struct {
	// DNS client pool.
	clients sync.Pool

	// System DNS resolvers.
	resolvers []string

	// Cache for our local (non-loopback) IP address.
	localIP     net.IP
	lastIPCheck time.Time

	// Logger.
	log *zap.SugaredLogger
}

func newResolver(logger *zap.SugaredLogger) (*resolver, error) {
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
		clients: sync.Pool{
			New: func() any {
				return &dns.Client{
					Timeout: queryTimeout,
				}
			},
		},
		resolvers: resolvers,
		log:       logger,
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
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	if len(query.Question) == 0 {
		return nil, fmt.Errorf("no questions in DNS query")
	}

	question := query.Question[0]

	var resp *dns.Msg
	var err error
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		resp, err = r.lookupIP(ctx, query)
	} else {
		resp, err = r.exchange(ctx, query, transport)
	}

	r.log.Debugf("\n-----query-----\n %v\n-----resp-----\n%v\n", query, resp)
	return resp, err
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
	// If host ndots == 1 remove it so we can use the system search domains.
	if strings.Count(host, ".") == 1 && strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}

	resp := new(dns.Msg)
	resp.SetReply(query)
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// Handle NXDOMAIN errors.
		if dnsErr, ok := err.(*net.DNSError); ok {
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

	// If we didn't find any IP, return a name error.
	if len(ips) == 0 {
		setNXDomain(resp, host)
	}

	return resp, nil
}

// Use miekg/dns to resolve the query. This is used for all DNS record types
// except A and AAAA.
// If multiple resolvers are configured, they are tried in order, waiting
// resolverTimeout between each attempt. As soon as one resolver succeeds, the
// response is returned.
// Multiple queries can be in-flight, until the context is cancelled.
func (r *resolver) exchange(ctx context.Context, query *dns.Msg, transport string) (*dns.Msg, error) {
	if transport != "udp" && transport != "tcp" {
		return nil, fmt.Errorf("invalid transport: %s", transport)
	}

	client := r.clients.Get().(*dns.Client)
	defer r.clients.Put(client)
	client.Net = transport

	respCh := make(chan *dns.Msg, 1)
	errCh := make(chan error, 1)

	// Query resolvers, waiting resolverDelay between each attempt.
	// The context may be cancelled by the caller before queries complete.
	// This can either mean we found a successful response, or a timeout occurred.
	go func() {
		for i, resolver := range r.resolvers {
			// Start a goroutine for each resolver.
			go func(resolver string) {
				r.log.Debugf("Resolving query using %s: %v", resolver, query)
				resp, _, err := client.ExchangeContext(ctx, query, resolver)
				if err != nil {
					r.log.Debugf("Failed to resolve query: %v", err)
					select {
					case errCh <- err:
					case <-ctx.Done():
					}
					return
				}
				select {
				case respCh <- resp:
				case <-ctx.Done():
				}
			}(resolver)

			// Wait before trying the next resolver (unless it's the last one).
			if i == len(r.resolvers)-1 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(resolverDelay):
			}
		}
	}()

	// Wait for responses. As soon as one succeeds, return it.
	var lastResp *dns.Msg
loop:
	for range r.resolvers {
		select {
		case resp := <-respCh:
			if resp.Rcode == dns.RcodeSuccess {
				return resp, nil
			}
			lastResp = resp
		case <-errCh:
		case <-ctx.Done():
			break loop
		}
	}

	// If we got here, we didn't get a successful response.
	// Return the last response we got, if any.
	if lastResp != nil {
		return lastResp, nil
	}

	return nil, fmt.Errorf("no response from resolvers")
}

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
			return r.localIP
		}

		// Use the first non-loopback IP address we find.
		for _, addr := range addrs {
			r.log.Info("Checking address: ", addr)

			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				r.localIP = ipnet.IP
				// Prefer RFC1918 addresses.
				if ipnet.IP.To4().IsPrivate() {
					break
				}
			}
		}
	}

	return r.localIP
}
