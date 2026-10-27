package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func newTestResolverForAddr(addr string) *resolver {
	return &resolver{
		log:            zap.NewNop().Sugar(),
		resolvers:      []string{addr},
		attemptTimeout: defaultAttemptTimeout,
	}
}

func newTestDNSServer(t *testing.T, rcode int) string {
	t.Helper()
	return newTestDNSServerHandler(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetRcode(req, rcode)
		if err := w.WriteMsg(resp); err != nil {
			t.Logf("write dns response: %v", err)
		}
	}))
}

func newTestDNSServerHandler(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(ready) },
		Handler:           handler,
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestExchangeCancellationClosesSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	queryRead := make(chan error, 1)
	closed := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			queryRead <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			queryRead <- err
			return
		}
		dnsConn := &dns.Conn{Conn: conn}
		_, err = dnsConn.ReadMsg()
		queryRead <- err
		if err != nil {
			return
		}
		_, err = dnsConn.ReadMsg()
		closed <- err
	}()

	r := newTestResolverForAddr(ln.Addr().String())
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeTXT)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.exchange(ctx, q, "tcp")
		done <- err
	}()
	select {
	case err := <-queryRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver did not receive query")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("exchange did not stop after cancellation")
	}
	select {
	case err := <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("resolver read after cancellation = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver socket remained open after cancellation")
	}
}

func TestLookupIPTimeoutReturnsServfail(t *testing.T) {
	r := newTestResolverForAddr("127.0.0.1:53")
	q := new(dns.Msg)
	q.SetQuestion("timeout.example.", dns.TypeA)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	resp, err := r.lookupIP(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestExchangeResolverOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		first  int
		second int
		want   int
	}{
		{name: "nxdomain", first: dns.RcodeNameError, second: dns.RcodeSuccess, want: dns.RcodeNameError},
		{name: "nodata", first: dns.RcodeSuccess, second: dns.RcodeNameError, want: dns.RcodeSuccess},
		{name: "servfail", first: dns.RcodeServerFailure, second: dns.RcodeSuccess, want: dns.RcodeSuccess},
		{name: "refused", first: dns.RcodeRefused, second: dns.RcodeSuccess, want: dns.RcodeSuccess},
		{name: "notimplemented", first: dns.RcodeNotImplemented, second: dns.RcodeSuccess, want: dns.RcodeSuccess},
		{name: "both_failed", first: dns.RcodeServerFailure, second: dns.RcodeRefused, want: dns.RcodeRefused},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestResolverForAddr(newTestDNSServer(t, tt.first))
			r.resolvers = append(r.resolvers, newTestDNSServer(t, tt.second))
			q := new(dns.Msg)
			q.SetQuestion("example.test.", dns.TypeTXT)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			resp, err := r.exchange(ctx, q, "udp")
			if err != nil {
				t.Fatal(err)
			}
			if resp.Rcode != tt.want {
				t.Fatalf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.want])
			}
		})
	}
}

func TestForwardTimeoutsReachThirdResolver(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	r := newTestResolverForAddr(silent.LocalAddr().String())
	r.attemptTimeout = 50 * time.Millisecond
	r.resolvers = append(r.resolvers, silent.LocalAddr().String(), newTestDNSServer(t, dns.RcodeSuccess))
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeTXT)
	resp, err := r.Forward(q, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

func TestForwardFailureReturnsServfail(t *testing.T) {
	r := &resolver{log: zap.NewNop().Sugar()}
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeTXT)
	resp, err := r.Forward(q, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestExchangeDeadlinePreservesFailureReply(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	r := newTestResolverForAddr(newTestDNSServer(t, dns.RcodeRefused))
	r.resolvers = append(r.resolvers, silent.LocalAddr().String(), newTestDNSServer(t, dns.RcodeSuccess))
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeTXT)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	resp, err := r.exchange(ctx, q, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestExchangeRemembersResolver(t *testing.T) {
	var firstCode, secondCode atomic.Int32
	var firstCalls, secondCalls atomic.Int32
	firstCode.Store(dns.RcodeServerFailure)
	secondCode.Store(dns.RcodeNameError)
	server := func(code, calls *atomic.Int32) string {
		return newTestDNSServerHandler(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			calls.Add(1)
			resp := new(dns.Msg)
			resp.SetRcode(req, int(code.Load()))
			if err := w.WriteMsg(resp); err != nil {
				t.Errorf("write dns response: %v", err)
			}
		}))
	}
	r := newTestResolverForAddr(server(&firstCode, &firstCalls))
	r.resolvers = append(r.resolvers, server(&secondCode, &secondCalls))
	exchange := func(want int) {
		q := new(dns.Msg)
		q.SetQuestion("example.test.", dns.TypeTXT)
		resp, err := r.exchange(t.Context(), q, "udp")
		if err != nil {
			t.Errorf("exchange: %v", err)
			return
		}
		if resp.Rcode != want {
			t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[want])
		}
	}
	exchange(dns.RcodeNameError)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { exchange(dns.RcodeNameError) })
	}
	wg.Wait()
	if got := firstCalls.Load(); got != 1 {
		t.Errorf("first resolver received %d queries, want 1", got)
	}
	if got := secondCalls.Load(); got != 9 {
		t.Errorf("second resolver received %d queries, want 9", got)
	}

	firstCode.Store(dns.RcodeSuccess)
	secondCode.Store(dns.RcodeRefused)
	exchange(dns.RcodeSuccess)
	exchange(dns.RcodeSuccess)
	if got := firstCalls.Load(); got != 3 {
		t.Errorf("recovered first resolver received %d queries, want 3", got)
	}
	if got := secondCalls.Load(); got != 10 {
		t.Errorf("failed second resolver received %d queries, want 10", got)
	}
}
