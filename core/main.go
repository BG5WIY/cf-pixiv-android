// Command cf-doh3-dns is a local DNS server that forwards every query to
// Cloudflare's DoH endpoint over HTTP/3 (QUIC), and injects "alpn=h3" hints
// into HTTPS/SVCB answers so clients try QUIC first.
//
// It listens on UDP and TCP (default 127.0.0.1:53) and is meant to be used as
// the upstream of systemd-resolved:
//
//	[Resolve]
//	DNS=127.0.0.1
//	Domains=~.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	version       = "1.0.0"
	maxDNSMessage = 65535
	maxHTTPBody   = 65536
	refreshPeriod = 30 * time.Minute
	probeTimeout  = 15 * time.Second
	defaultDoh    = "https://cloudflare-dns.com/dns-query"
)

// seedIPs are known-good Cloudflare DoH edge addresses. They are only a
// bootstrap: once a query succeeds, the real A/AAAA records of the DoH
// hostname are fetched through the DoH connection itself, so the program
// never depends on the system resolver (which would create a loop).
var seedIPs = []string{
	"104.16.248.249",
	"104.16.249.249",
	"104.16.250.249",
	"104.16.251.249",
}

type config struct {
	listen      string
	dohListen   string
	dohURL      string
	dohHost     string
	dohPort     string
	dohIPs      string
	bootstrap   string
	h3Hint      string
	cacheSize   int
	maxTTL      uint
	timeout     time.Duration
	verbose     bool
	probe       string
	probeType   string
	refreshTime time.Duration

	// Hijack rule: i.pximg.net is answered locally.
	hijackName   string
	hijackLANIP  string
	hijackRemote string
	hijackTTL    uint
	lanCIDRs     string

	// HTTP/3 forward proxy for clients that can't do h3 themselves (WebView)
	proxyListen string
}

type stats struct {
	queries   atomic.Uint64
	cacheHits atomic.Uint64
	errors    atomic.Uint64
}

type App struct {
	cfg       config
	transport *http3.Transport
	cache     *cache
	stats     stats

	mu  sync.RWMutex
	ips []string

	lanNets   []*net.IPNet
	remoteMu  sync.Mutex
	remoteIPs []net.IP
	remoteExp time.Time
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := parseFlags()

	app, err := newApp(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.bootstrap != "" {
		app.bootstrapResolve(ctx)
	}

	if cfg.probe != "" {
		os.Exit(app.runProbe(ctx))
	}

	// Refresh the DoH edge addresses through DoH itself (no system DNS).
	go app.refreshLoop(ctx)
	go app.statsLoop(ctx)
	go app.healthCheck(ctx)
	if cfg.proxyListen != "" {
		go app.serveHttp3Proxy(ctx, cfg.proxyListen)
	}

	if err := app.serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:53", "UDP/TCP address to serve DNS on")
	flag.StringVar(&cfg.dohListen, "doh-listen", "", "HTTP listen address for DoH (/dns-query), e.g. 127.0.0.1:1053; empty disables")
	flag.StringVar(&cfg.dohURL, "doh", defaultDoh, "DoH endpoint (must support HTTP/3)")
	flag.StringVar(&cfg.dohIPs, "doh-ip", "", "comma-separated DoH edge IPs (overrides built-in bootstrap)")
	flag.StringVar(&cfg.bootstrap, "bootstrap-dns", "", "plain DNS used only if all bootstrap IPs fail, e.g. 192.168.1.1:53")
	flag.StringVar(&cfg.h3Hint, "h3-hint", "inject", "HTTPS/SVCB hint mode: inject (synthesize when absent), amend (only extend existing), off")
	flag.IntVar(&cfg.cacheSize, "cache-size", 8192, "max cached responses (0 disables the cache)")
	flag.UintVar(&cfg.maxTTL, "max-ttl", 600, "upper bound for cached TTL, seconds")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-query upstream timeout")
	flag.BoolVar(&cfg.verbose, "v", false, "verbose query logging")
	flag.StringVar(&cfg.probe, "probe", "", "resolve NAME once through the DoH upstream, print the answer, and exit")
	flag.StringVar(&cfg.probeType, "probe-type", "A", "record type for -probe")
	flag.DurationVar(&cfg.refreshTime, "refresh", refreshPeriod, "how often to refresh DoH edge IPs through DoH")
	flag.StringVar(&cfg.hijackName, "hijack", "i.pximg.net", "domain answered locally (empty disables the rule)")
	flag.StringVar(&cfg.hijackLANIP, "hijack-lan-ip", "192.168.1.3", "A record returned to LAN clients for the hijacked domain")
	flag.StringVar(&cfg.hijackRemote, "hijack-remote", "hugengron.cn", "A records of this domain are returned to non-LAN clients")
	flag.UintVar(&cfg.hijackTTL, "hijack-ttl", 60, "TTL of hijacked answers, seconds")
	flag.StringVar(&cfg.lanCIDRs, "lan-cidr", "192.168.1.0/24", "comma-separated CIDRs treated as LAN")
	flag.StringVar(&cfg.proxyListen, "proxy-listen", "", "HTTP/3 forward proxy listen address, e.g. 127.0.0.1:8445")
	flag.Parse()

	if cfg.h3Hint != "inject" && cfg.h3Hint != "amend" && cfg.h3Hint != "off" {
		log.Fatalf("invalid -h3-hint %q (want inject, amend or off)", cfg.h3Hint)
	}
	if cfg.hijackName != "" && net.ParseIP(cfg.hijackLANIP) == nil {
		log.Fatalf("invalid -hijack-lan-ip %q", cfg.hijackLANIP)
	}

	u, err := url.Parse(cfg.dohURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		log.Fatalf("invalid -doh URL %q", cfg.dohURL)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Host, "443"
	}
	cfg.dohHost = strings.Trim(host, "[]")
	cfg.dohPort = port

	return cfg
}

func newApp(cfg config) (*App, error) {
	app := &App{cfg: cfg}

	if cfg.dohIPs != "" {
		for _, s := range strings.Split(cfg.dohIPs, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				app.ips = append(app.ips, s)
			}
		}
	}
	if len(app.ips) == 0 {
		app.ips = slices.Clone(seedIPs)
	}

	nets, err := parseCIDRs(cfg.lanCIDRs)
	if err != nil {
		return nil, err
	}
	app.lanNets = nets

	if cfg.cacheSize > 0 {
		app.cache = newCache(cfg.cacheSize, time.Duration(cfg.maxTTL)*time.Second)
	}

	tlsCfg := &tls.Config{
		ServerName: cfg.dohHost,
		MinVersion: tls.VersionTLS13,
	}
	quicCfg := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	}

	app.transport = &http3.Transport{
		TLSClientConfig:    tlsCfg,
		QUICConfig:         quicCfg,
		Dial:               app.dial,
		DisableCompression: true,
	}
	return app, nil
}

// ---------------------------------------------------------------- DoH client

func (a *App) snapshotIPs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.Clone(a.ips)
}

func (a *App) setIPs(ips []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ips = ips
}

// dial connects to whichever DoH edge IP answers first. addr is the URL host
// (cloudflare-dns.com:443); its host part is deliberately ignored so we never
// rely on the system resolver, while TLS still verifies the real hostname.
func (a *App) dial(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = a.cfg.dohPort
	}
	ips := a.snapshotIPs()
	if len(ips) == 0 {
		return nil, errors.New("no DoH edge IPs configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn *quic.Conn
		err  error
	}
	ch := make(chan result, len(ips))
	for _, ip := range ips {
		go func(ip string) {
			c, err := quic.DialAddr(ctx, net.JoinHostPort(ip, port), tlsCfg, qcfg)
			ch <- result{c, err}
		}(ip)
	}

	var (
		conns   []*quic.Conn
		lastErr error
	)
	for range ips {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		conns = append(conns, r.conn)
		if len(conns) == 1 {
			cancel() // stop the losers
		}
	}
	if len(conns) == 0 {
		if lastErr == nil {
			lastErr = errors.New("dial failed")
		}
		return nil, lastErr
	}
	for _, c := range conns[1:] {
		_ = c.CloseWithError(0, "unused")
	}
	return conns[0], nil
}

func (a *App) dohQuery(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	raw, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.dohURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/dns-message")
	hreq.Header.Set("Accept", "application/dns-message")
	hreq.Header.Set("User-Agent", "cf-doh3-dns/"+version)

	hresp, err := a.transport.RoundTrip(hreq)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(hresp.Body, maxHTTPBody))
	if err != nil {
		return nil, err
	}
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d: %s", hresp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	if ct := hresp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("unexpected content-type %q", ct)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}

// extractIPs pulls A/AAAA answers out of a response.
func extractIPs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		// 只用 IPv4 边缘 IP：移动网络/VPN 下 IPv6 常不可达，
		// 混入 AAAA 会让 QUIC 连接直接 "no route to host"。
		if v, ok := rr.(*dns.A); ok {
			out = append(out, v.A.String())
		}
	}
	return out
}

func (a *App) refreshLoop(ctx context.Context) {
	// Give the first real query a chance to establish the QUIC connection.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}
	a.refreshIPs(ctx)

	t := time.NewTicker(a.cfg.refreshTime)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.refreshIPs(ctx)
		}
	}
}

// refreshIPs re-resolves the DoH hostname through the DoH connection itself.
func (a *App) refreshIPs(ctx context.Context) {
	var found []string
	for _, qtype := range []uint16{dns.TypeA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(a.cfg.dohHost), qtype)
		q.RecursionDesired = true
		q.Id = dns.Id()

		qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		resp, err := a.dohQuery(qctx, q)
		cancel()
		if err != nil {
			a.logf("refresh %s: %v", dns.TypeToString[qtype], err)
			continue
		}
		found = append(found, extractIPs(resp)...)
	}

	found = slices.Compact(slices.Sorted(slices.Values(found)))
	if len(found) == 0 {
		return
	}
	a.setIPs(found)
	a.logf("DoH edge IPs refreshed via DoH: %s", strings.Join(found, ", "))
}

// bootstrapResolve is the last-resort path for environments where none of the
// built-in seed IPs work: a plain DNS server is asked for the DoH hostname.
// It is only used at startup and never replaces the self-refresh through DoH.
func (a *App) bootstrapResolve(ctx context.Context) {
	var found []string
	for _, qtype := range []uint16{dns.TypeA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(a.cfg.dohHost), qtype)
		q.RecursionDesired = true
		q.Id = dns.Id()

		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		resp, _, err := c.ExchangeContext(qctx, q, a.cfg.bootstrap)
		cancel()
		if err != nil {
			a.logf("bootstrap %s via %s: %v", dns.TypeToString[qtype], a.cfg.bootstrap, err)
			continue
		}
		found = append(found, extractIPs(resp)...)
	}

	found = slices.Compact(slices.Sorted(slices.Values(found)))
	if len(found) == 0 {
		a.logf("bootstrap-dns %s returned no addresses, keeping seed IPs", a.cfg.bootstrap)
		return
	}
	a.setIPs(found)
	a.logf("DoH edge IPs from bootstrap %s: %s", a.cfg.bootstrap, strings.Join(found, ", "))
}

// ---------------------------------------------------------------- DNS server

// serveHttp3Proxy accepts plain HTTP on loopback and forwards each request to
// the origin over HTTP/3. WebView won't consult HTTPS/SVCB records, so without
// this the page can only try TCP:443, which is reset in restricted networks.
func (a *App) serveHttp3Proxy(ctx context.Context, addr string) {
	clients := sync.Map{}
	getClient := func(host string) *http.Client {
		if v, ok := clients.Load(host); ok {
			return v.(*http.Client)
		}
		rt := &http3.Transport{
			TLSClientConfig: &tls.Config{ServerName: host},
		}
		c := &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		clients.Store(host, c)
		return c
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 客户端用 127.0.0.1 连接，真实目标域名由 X-Forwarded-Host 指定
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		if i := strings.IndexByte(host, ':'); i > 0 {
			host = host[:i]
		}
		if host == "" {
			http.Error(w, "missing Host", http.StatusBadRequest)
			return
		}
		target := "https://" + host + r.URL.RequestURI()
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for k, vv := range r.Header {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Accept-Encoding") {
				continue
			}
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		req.Host = host
		resp, err := getClient(host).Do(req)
		if err != nil {
			a.logf("h3 proxy %s %s: %v", r.Method, target, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	a.logf("http3 proxy listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.logf("http3 proxy: %v", err)
	}
}

func (a *App) serve(ctx context.Context) error {
	udpSrv := &dns.Server{
		Addr:         a.cfg.listen,
		Net:          "udp",
		Handler:      udpHandler{a},
		UDPSize:      maxDNSMessage,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	tcpSrv := &dns.Server{
		Addr:         a.cfg.listen,
		Net:          "tcp",
		Handler:      a,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errc := make(chan error, 3)
	start := func(name string, srv *dns.Server) {
		go func() {
			a.logf("%s listening on %s", name, a.cfg.listen)
			errc <- srv.ListenAndServe()
		}()
	}
	start("udp", udpSrv)
	start("tcp", tcpSrv)

	var httpSrv *http.Server
	if a.cfg.dohListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", a.dohHandler)
		httpSrv = &http.Server{
			Addr:              a.cfg.dohListen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
		go func() {
			a.logf("DoH listening on http://%s/dns-query", a.cfg.dohListen)
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	var serr error
	select {
	case <-ctx.Done():
		a.logf("shutting down")
	case serr = <-errc:
		if serr != nil {
			if errors.Is(serr, syscall.EACCES) || errors.Is(serr, os.ErrPermission) {
				serr = fmt.Errorf("%w (binding %s needs root or CAP_NET_BIND_SERVICE; run with sudo or setcap)", serr, a.cfg.listen)
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = udpSrv.ShutdownContext(shutdownCtx)
	_ = tcpSrv.ShutdownContext(shutdownCtx)
	if httpSrv != nil {
		_ = httpSrv.Shutdown(shutdownCtx)
	}
	_ = a.transport.Close()
	return serr
}

// udpHandler marks replies as UDP so they are truncated to the client's
// advertised EDNS0 buffer size.
type udpHandler struct{ app *App }

func (h udpHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) { h.app.serveDNS(w, req, true) }

func (a *App) ServeDNS(w dns.ResponseWriter, req *dns.Msg) { a.serveDNS(w, req, false) }

func (a *App) serveDNS(w dns.ResponseWriter, req *dns.Msg, udp bool) {
	a.stats.queries.Add(1)

	if len(req.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	if a.isHijacked(q) {
		if m := a.hijackResponse(w, req); m != nil {
			m.Id = req.Id
			a.writeReply(w, req, m, udp)
			return
		}
	}
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNotImplemented)
		_ = w.WriteMsg(m)
		return
	}

	start := time.Now()
	key := cacheKey(q, dnssecOK(req))
	cacheHit := false

	var resp *dns.Msg
	if a.cache != nil {
		if m, ok := a.cache.get(key); ok {
			resp = m
			cacheHit = true
			a.stats.cacheHits.Add(1)
		}
	}

	if resp == nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.cfg.timeout)
		m, err := a.dohQuery(ctx, req)
		cancel()
		if err != nil {
			a.stats.errors.Add(1)
			a.logf("upstream %s %s: %v", q.Name, typeString(q.Qtype), err)
			_ = w.WriteMsg(servfail(req))
			return
		}
		a.applyH3Hints(m)
		if a.cache != nil {
			a.cache.put(key, m)
		}
		resp = m
	}

	resp.Id = req.Id
	a.writeReply(w, req, resp, udp)

	if a.cfg.verbose {
		a.logf("%s %s -> %d answers%s in %s", q.Name, typeString(q.Qtype),
			len(resp.Answer), hitSuffix(cacheHit), time.Since(start).Round(time.Microsecond))
	}
}

func (a *App) writeReply(w dns.ResponseWriter, req, resp *dns.Msg, udp bool) {
	if udp {
		size := 512
		if opt := req.IsEdns0(); opt != nil {
			if n := int(opt.UDPSize()); n > size {
				size = n
			}
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		a.logf("write reply: %v", err)
	}
}

func servfail(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}

// ---------------------------------------------------------------- DoH server

// dohHandler serves RFC 8484 DNS over HTTPS. TLS is terminated by the reverse
// proxy in front of it, so this listens on plain HTTP on loopback.
func (a *App) dohHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}

	var (
		raw []byte
		err error
	)
	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, maxDNSMessage+1))
	case http.MethodGet:
		enc := r.URL.Query().Get("dns")
		if enc == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(enc, "="))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(raw) == 0 || len(raw) > maxDNSMessage {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	if len(req.Question) != 1 {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	rw := &memResponseWriter{remote: &net.UDPAddr{IP: clientIPFromRequest(r)}}
	a.serveDNS(rw, req, false)
	if rw.msg == nil {
		http.Error(w, "no answer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(rw.msg)))
	_, _ = w.Write(rw.msg)
}

// memResponseWriter captures the DNS response produced by serveDNS so it can
// be returned as an HTTP body.
type memResponseWriter struct {
	remote net.Addr
	msg    []byte
}

func (w *memResponseWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *memResponseWriter) RemoteAddr() net.Addr {
	if w.remote == nil {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	return w.remote
}
func (w *memResponseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	w.msg = b
	return nil
}
func (w *memResponseWriter) Write(b []byte) (int, error) {
	w.msg = append([]byte(nil), b...)
	return len(b), nil
}
func (w *memResponseWriter) Close() error        { return nil }
func (w *memResponseWriter) TsigStatus() error   { return nil }
func (w *memResponseWriter) TsigTimersOnly(bool) {}
func (w *memResponseWriter) Hijack()             {}

// clientIPFromRequest recovers the original client address that nginx passes
// through X-Forwarded-For, so the LAN/remote hijack split still works.
func clientIPFromRequest(r *http.Request) net.IP {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if v := r.Header.Get(h); v != "" {
			first := strings.TrimSpace(strings.Split(v, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func dnssecOK(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

func cacheKey(q dns.Question, do bool) string {
	return strings.ToLower(q.Name) + "|" + strconv.Itoa(int(q.Qtype)) + "|" +
		strconv.Itoa(int(q.Qclass)) + "|" + strconv.FormatBool(do)
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return strconv.Itoa(int(t))
}

func hitSuffix(hit bool) string {
	if hit {
		return " [cache]"
	}
	return ""
}

// ---------------------------------------------------------------- hijack rules

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid LAN CIDR %q: %w", part, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func (a *App) isLAN(ip net.IP) bool {
	for _, n := range a.lanNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(w dns.ResponseWriter) net.IP {
	switch v := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (a *App) isHijacked(q dns.Question) bool {
	return a.cfg.hijackName != "" &&
		q.Qclass == dns.ClassINET &&
		strings.EqualFold(q.Name, dns.Fqdn(a.cfg.hijackName))
}

// hijackResponse answers the hijacked name locally: LAN clients are pointed at
// the local reverse proxy, everybody else at the public endpoint's IPv4.
// AAAA and HTTPS deliberately return NODATA so the real address can not leak
// through a hint or an IPv6 record and bypass the redirect.
func (a *App) hijackResponse(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}
	q := req.Question[0]

	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	// 回显 EDNS：部分 resolver(尤其 Android netd) 会丢弃缺少 OPT 的响应，
	// 丢弃后回退到物理网络 DNS，劫持就失效了。
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}

	switch q.Qtype {
	case dns.TypeA:
		ips, mode := a.hijackAddresses(w)
		if ips == nil {
			m.Rcode = dns.RcodeServerFailure
			return m
		}
		ttl := uint32(a.cfg.hijackTTL)
		for _, ip := range ips {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip,
			})
		}
		a.logf("hijack %s A from %s -> %s (%s)", q.Name, remoteIPString(w), ipsString(ips), mode)
		return m

	default:
		// AAAA, HTTPS, CNAME, ANY, ... must not reveal the real endpoint.
		return m // NODATA
	}
}

func (a *App) hijackAddresses(w dns.ResponseWriter) ([]net.IP, string) {
	if ip := remoteIP(w); ip != nil && a.isLAN(ip) {
		target := net.ParseIP(a.cfg.hijackLANIP)
		if target == nil {
			return nil, ""
		}
		return []net.IP{target}, "lan"
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.timeout)
	defer cancel()
	ips, err := a.remoteA(ctx)
	if err != nil {
		a.logf("hijack: resolving %s: %v", a.cfg.hijackRemote, err)
		return nil, ""
	}
	return ips, "remote"
}

// remoteA resolves the public endpoint through the same DoH upstream and
// caches the answer for its TTL (30s..300s).
func (a *App) remoteA(ctx context.Context) ([]net.IP, error) {
	a.remoteMu.Lock()
	if len(a.remoteIPs) > 0 && time.Now().Before(a.remoteExp) {
		ips := slices.Clone(a.remoteIPs)
		a.remoteMu.Unlock()
		return ips, nil
	}
	a.remoteMu.Unlock()

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(a.cfg.hijackRemote), dns.TypeA)
	q.RecursionDesired = true
	q.Id = dns.Id()

	resp, err := a.dohQuery(ctx, q)
	if err != nil {
		return nil, err
	}

	var (
		ips []net.IP
		ttl uint32 = 60
	)
	for _, rr := range resp.Answer {
		if v, ok := rr.(*dns.A); ok {
			ips = append(ips, v.A)
			if v.Hdr.Ttl > 0 && v.Hdr.Ttl < ttl {
				ttl = v.Hdr.Ttl
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A record for %s", a.cfg.hijackRemote)
	}
	if ttl < 30 {
		ttl = 30
	}
	if ttl > 300 {
		ttl = 300
	}

	a.remoteMu.Lock()
	a.remoteIPs = ips
	a.remoteExp = time.Now().Add(time.Duration(ttl) * time.Second)
	a.remoteMu.Unlock()
	return ips, nil
}

func remoteIPString(w dns.ResponseWriter) string {
	if ip := remoteIP(w); ip != nil {
		return ip.String()
	}
	return w.RemoteAddr().String()
}

func ipsString(ips []net.IP) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}

// ------------------------------------------------------------- h3 hint logic

// applyH3Hints makes sure an HTTPS/SVCB answer advertises HTTP/3.
//
// Note: mutating a signed HTTPS RR invalidates its RRSIG, so any covering
// RRSIG is dropped and the AD bit cleared. Clients verify DNSSEC themselves;
// systemd-resolved is expected to run with DNSSEC=no when this is enabled.
func (a *App) applyH3Hints(m *dns.Msg) {
	if a.cfg.h3Hint == "off" || m.Rcode != dns.RcodeSuccess || len(m.Question) == 0 {
		return
	}
	q := m.Question[0]
	if q.Qtype != dns.TypeHTTPS || q.Qclass != dns.ClassINET {
		return
	}

	modified := false
	haveServiceMode := false
	for _, rr := range m.Answer {
		h, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		if h.Priority == 0 {
			// AliasMode: SvcParams must be empty, nothing sensible to inject.
			continue
		}
		haveServiceMode = true
		haveAlpn := false
		for _, kv := range h.Value {
			alpn, ok := kv.(*dns.SVCBAlpn)
			if !ok {
				continue
			}
			haveAlpn = true
			if !slices.Contains(alpn.Alpn, "h3") {
				alpn.Alpn = append(alpn.Alpn, "h3")
				modified = true
			}
		}
		if !haveAlpn {
			h.Value = append(h.Value, &dns.SVCBAlpn{Alpn: []string{"h3"}})
			modified = true
		}
	}

	if !haveServiceMode && a.cfg.h3Hint == "inject" {
		// NODATA for HTTPS: synthesize a ServiceMode record that only says
		// "h3 is available". Clients still resolve A/AAAA separately.
		// If the answer is a CNAME chain, the record must belong to the
		// chain's final name, not to the queried alias.
		owner := q.Name
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				owner = c.Target
			}
		}
		m.Answer = append(m.Answer, &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3"}}},
			},
		})
		m.Ns = nil // drop the NODATA SOA, this is a positive answer now
		modified = true
	}

	if !modified {
		return
	}

	m.AuthenticatedData = false
	kept := m.Answer[:0]
	for _, rr := range m.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeHTTPS {
			continue
		}
		kept = append(kept, rr)
	}
	m.Answer = kept
}

// -------------------------------------------------------------------- cache

type cacheEntry struct {
	msg    *dns.Msg
	stored time.Time
	exp    time.Time
}

type cache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	max     int
	ttlCap  time.Duration
}

func newCache(max int, ttlCap time.Duration) *cache {
	return &cache{entries: make(map[string]*cacheEntry, max), max: max, ttlCap: ttlCap}
}

func (c *cache) get(key string) (*dns.Msg, bool) {
	now := time.Now()
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	if now.After(e.exp) {
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	c.mu.Unlock()

	m := e.msg.Copy()
	ageTTLs(m, uint32(now.Sub(e.stored).Seconds()))
	return m, true
}

func (c *cache) put(key string, m *dns.Msg) {
	ttl, ok := responseTTL(m)
	if !ok || ttl == 0 {
		return
	}
	if d := time.Duration(ttl) * time.Second; d > c.ttlCap {
		ttl = uint32(c.ttlCap / time.Second)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		// Cheap eviction: drop expired entries, then an arbitrary batch.
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.exp) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			n := 0
			for k := range c.entries {
				delete(c.entries, k)
				if n++; n > c.max/4 {
					break
				}
			}
		}
	}
	c.entries[key] = &cacheEntry{
		msg:    m.Copy(),
		stored: time.Now(),
		exp:    time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// responseTTL returns the smallest TTL worth caching, following the SOA
// negative-caching rule for empty answer sections.
func responseTTL(m *dns.Msg) (uint32, bool) {
	if len(m.Answer) > 0 {
		var minTTL uint32 = 1<<32 - 1
		for _, rr := range m.Answer {
			if t := rr.Header().Ttl; t < minTTL {
				minTTL = t
			}
		}
		return minTTL, true
	}

	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			return ttl, true
		}
	}
	return 0, false
}

func ageTTLs(m *dns.Msg, age uint32) {
	ageRR := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			h := rr.Header()
			if h.Ttl > age {
				h.Ttl -= age
			} else {
				h.Ttl = 0
			}
		}
	}
	ageRR(m.Answer)
	ageRR(m.Ns)
	ageRR(m.Extra)
}

// --------------------------------------------------------------- diagnostics

func (a *App) logf(format string, args ...any) {
	log.Printf(format, args...)
}

func (a *App) statsLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.cfg.verbose {
				a.logf("stats: %d queries, %d cache hits, %d upstream errors",
					a.stats.queries.Load(), a.stats.cacheHits.Load(), a.stats.errors.Load())
			}
		}
	}
}

func (a *App) healthCheck(ctx context.Context) {
	q := new(dns.Msg)
	q.SetQuestion("cloudflare-dns.com.", dns.TypeA)
	q.Id = dns.Id()

	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	start := time.Now()
	resp, err := a.dohQuery(cctx, q)
	if err != nil {
		a.logf("health check FAILED: %v", err)
		return
	}
	a.logf("health check ok: %d answers in %s over HTTP/3", len(resp.Answer), time.Since(start).Round(time.Millisecond))
}

func (a *App) runProbe(ctx context.Context) int {
	qtype, ok := dns.StringToType[strings.ToUpper(a.cfg.probeType)]
	if !ok {
		log.Printf("unknown probe type %q", a.cfg.probeType)
		return 2
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(a.cfg.probe), qtype)
	q.Id = dns.Id()

	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	resp, err := a.dohQuery(cctx, q)
	if err != nil {
		log.Printf("probe failed: %v", err)
		return 1
	}
	if resp.Rcode != dns.RcodeSuccess {
		log.Printf("probe rcode: %s", dns.RcodeToString[resp.Rcode])
		return 1
	}
	for _, rr := range resp.Answer {
		fmt.Println(rr.String())
	}
	return 0
}
