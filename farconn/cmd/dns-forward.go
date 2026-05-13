package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const resolverStagger = 500 * time.Millisecond

var (
	dnsListen    string
	dnsUpstreams []string
	dnsNoIPv6    bool
)

func init() {
	dnsForwardCmd.Flags().StringVar(&dnsListen, "listen", "127.0.0.1:1053", "Listen address (host:port)")
	dnsForwardCmd.Flags().StringSliceVar(&dnsUpstreams, "upstream", []string{"127.0.0.11:53"}, "Upstream resolvers (comma-separated or repeated)")
	dnsForwardCmd.Flags().BoolVar(&dnsNoIPv6, "no-ipv6", false, "Filter AAAA queries (return empty responses)")
	rootCmd.AddCommand(dnsForwardCmd)
}

var dnsForwardCmd = &cobra.Command{
	Use:   "dns-forward",
	Short: "Forward DNS queries to an upstream resolver",
	Run:   runDNSForward,
}

func dnsExchange(c *dns.Client, r *dns.Msg, upstreams []string) (*dns.Msg, error) {
	if len(upstreams) == 1 {
		resp, _, err := c.Exchange(r, upstreams[0])
		return resp, err
	}

	type result struct {
		resp *dns.Msg
		err  error
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	ch := make(chan result, len(upstreams))
	var wg sync.WaitGroup

launch:
	for i, upstream := range upstreams {
		wg.Go(func() {
			resp, _, err := c.ExchangeContext(ctx, r, upstream)
			select {
			case ch <- result{resp, err}:
				if err == nil {
					cancel()
				}
			case <-ctx.Done():
			}
		})

		if i < len(upstreams)-1 {
			select {
			case <-ctx.Done():
				break launch
			case <-time.After(resolverStagger):
			}
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var lastErr error
	for res := range ch {
		if res.err == nil {
			return res.resp, nil
		}
		lastErr = res.err
	}
	return nil, lastErr
}

func runDNSForward(cmd *cobra.Command, args []string) {
	upstreams := make([]string, 0, len(dnsUpstreams))
	for _, u := range dnsUpstreams {
		u = strings.TrimSpace(u)
		if u != "" {
			upstreams = append(upstreams, u)
		}
	}
	if len(upstreams) == 0 {
		fmt.Fprintln(os.Stderr, "dns-forward: no upstream resolvers specified")
		os.Exit(1)
	}

	udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if dnsNoIPv6 && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAAAA {
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
			return
		}

		c := udpClient
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			c = tcpClient
		}

		resp, err := dnsExchange(c, r, upstreams)
		if err != nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}

		_ = w.WriteMsg(resp)
	})

	udpServer := &dns.Server{
		Addr:    dnsListen,
		Net:     "udp",
		Handler: handler,
	}
	tcpServer := &dns.Server{
		Addr:        dnsListen,
		Net:         "tcp",
		Handler:     handler,
		ReadTimeout: 30 * time.Second,
	}

	ready := make(chan struct{}, 2)
	udpServer.NotifyStartedFunc = func() { ready <- struct{}{} }
	tcpServer.NotifyStartedFunc = func() { ready <- struct{}{} }

	errCh := make(chan error, 2)
	go func() { errCh <- udpServer.ListenAndServe() }()
	go func() { errCh <- tcpServer.ListenAndServe() }()

	for range 2 {
		select {
		case err := <-errCh:
			fmt.Fprintf(os.Stderr, "dns-forward: %v\n", err)
			os.Exit(1)
		case <-ready:
		}
	}

	ipv6Status := "enabled"
	if dnsNoIPv6 {
		ipv6Status = "disabled (AAAA filtered)"
	}
	fmt.Fprintf(os.Stderr, "dns-forward: listening on %s, upstreams: %s, ipv6: %s\n",
		dnsListen, strings.Join(upstreams, ","), ipv6Status)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-errCh:
		fmt.Fprintf(os.Stderr, "dns-forward: %v\n", err)
		os.Exit(1)
	case <-sig:
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}
}
