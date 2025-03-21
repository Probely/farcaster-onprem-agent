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

	if len(r.resolvers) == 0 {
		return nil, fmt.Errorf("no resolvers configured")
	}

	client := r.clients.Get().(*dns.Client)
	defer r.clients.Put(client)
	client.Net = transport

	// Encapsulate resolver results.
	type resolverResult struct {
		resp     *dns.Msg
		err      error
		resolver string
	}

	resultCh := make(chan resolverResult, len(r.resolvers))

	// Create a child context to allow cancellation of resolver goroutines.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// We'll store the last non-success response here in case we need to
	// return it if no resolver returns RcodeSuccess.
	var lastResp *dns.Msg

	// We'll collect any errors that occur from resolvers.
	var errs []error
	var mu sync.Mutex // Protects errs from concurrent appends

outerLoop:
	for i, resolver := range r.resolvers {
		wg.Add(1)
		go func(resolver string) {
			defer wg.Done()

			r.log.Debugf("Attempting to resolve query using resolver %s", resolver)
			resp, _, err := client.ExchangeContext(ctx, query, resolver)
			if err != nil {
				r.log.Errorf("Resolver %s encountered an error: %v", resolver, err)
				select {
				case resultCh <- resolverResult{err: fmt.Errorf("resolver %s: %w", resolver, err), resolver: resolver}:
				case <-ctx.Done():
					r.log.Debugf("Context canceled before sending error for resolver %s", resolver)
				}
				return
			}

			if resp.Rcode != dns.RcodeSuccess {
				// Store this as a "last non-success response," in case no one else succeeds
				r.log.Warnf("Resolver %s returned non-success Rcode: %d", resolver, resp.Rcode)
				select {
				case resultCh <- resolverResult{
					resp:     resp,
					err:      fmt.Errorf("resolver %s returned Rcode %d", resolver, resp.Rcode),
					resolver: resolver,
				}:
				case <-ctx.Done():
					r.log.Debugf("Context canceled before sending Rcode for resolver %s", resolver)
				}
				return
			}

			// If we get a successful Rcode, send it and cancel other resolvers.
			select {
			case resultCh <- resolverResult{resp: resp, resolver: resolver}:
				r.log.Debugf("Resolver %s succeeded, canceling other resolvers", resolver)
				cancel()
			case <-ctx.Done():
				r.log.Debugf("Context canceled before sending response for resolver %s", resolver)
			}
		}(resolver)

		// Wait "delay" ms between starting each resolver, except after the last one.
		if i < len(r.resolvers)-1 {
			select {
			case <-ctx.Done():
				// Break from the outer for-loop immediately if context is canceled
				break outerLoop
			case <-time.After(resolverDelay):
			}
		}
	}

	// Close the result channel once all resolver goroutines have finished
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results until we succeed or until everything finishes/cancels
	for {
		select {
		case result, ok := <-resultCh:
			if !ok {
				// resultCh is closed, no more results
				resultCh = nil
				continue
			}

			// If we got a successful response, return immediately.
			if result.resp != nil && result.resp.Rcode == dns.RcodeSuccess {
				r.log.Debugf("Received successful response from resolver %s", result.resolver)
				return result.resp, nil
			}

			// Otherwise, capture the error and possibly store the non-success resp.
			if result.err != nil {
				r.log.Warnf("Received error from resolver %s: %v", result.resolver, result.err)
				mu.Lock()
				errs = append(errs, result.err)
				mu.Unlock()
				if result.resp != nil {
					// Keep track of last non-successful response (e.g., NXDOMAIN).
					// This can be returned if no success eventually arrives.
					lastResp = result.resp
				}
			}

		case <-ctx.Done():
			r.log.Warn("Context canceled or deadline exceeded")

			// If we got a non-success response before everything died, return that
			if lastResp != nil {
				r.log.Debug("Returning last received response despite non-success Rcode")
				return lastResp, nil
			}

			// Otherwise, all resolvers must have failed or we never got a response
			mu.Lock()
			defer mu.Unlock()
			if len(errs) > 0 {
				r.log.Error("All resolvers failed")
				return nil, fmt.Errorf("all resolvers failed: %v", errs)
			}
			r.log.Error("No response received from resolvers")
			return nil, ctx.Err()
		}

		// Once resultCh is nil, we've read all results
		if resultCh == nil {
			break
		}
	}

	// Finished reading all results, but no success found
	if lastResp != nil {
		r.log.Debug("Returning last received response (non-success) after all resolvers completed")
		return lastResp, nil
	}

	mu.Lock()
	defer mu.Unlock()
	if len(errs) > 0 {
		r.log.Error("All resolvers failed with errors, no success response")
		return nil, fmt.Errorf("all resolvers failed: %v", errs)
	}

	r.log.Error("No response received from any resolver")
	return nil, fmt.Errorf("no response from resolvers")
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
