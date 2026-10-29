package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var dialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control:   dialControl,
}

// idleTimeout closes tunnels with no traffic in either direction for this
// long. Zero disables it. Set from the -idle-timeout flag.
var idleTimeout = 5 * time.Minute

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address; empty disables it")
	httpAddr := flag.String("http", "127.0.0.1:8080", "HTTP/HTTPS proxy listen address; empty disables it")
	authUser := flag.String("auth-user", "", "proxy authentication username (or SIMPLE_PROXY_USER)")
	authPassword := flag.String("auth-password", "", "proxy authentication password (or SIMPLE_PROXY_PASSWORD)")
	allowClients := flag.String("allow-clients", "", "comma-separated client IPs/CIDRs allowed to connect; empty allows all")
	flag.BoolVar(&denyPrivateDestinations, "deny-private", false, "refuse to proxy to loopback, private, link-local and other non-public addresses")
	flag.DurationVar(&idleTimeout, "idle-timeout", idleTimeout, "close tunnels idle in both directions for this long; 0 disables")
	flag.Parse()

	if *socksAddr == "" && *httpAddr == "" {
		log.Fatal("both SOCKS5 and HTTP proxy are disabled")
	}
	username := firstNonEmpty(*authUser, os.Getenv("SIMPLE_PROXY_USER"))
	password := firstNonEmpty(*authPassword, os.Getenv("SIMPLE_PROXY_PASSWORD"))
	auth, err := newCredentials(username, password)
	if err != nil {
		log.Fatal(err)
	}
	if auth.enabled() {
		log.Print("proxy authentication enabled")
	}
	allowlist, err := parseClientAllowlist(*allowClients)
	if err != nil {
		log.Fatal(err)
	}
	if len(allowlist) > 0 {
		log.Printf("client allowlist: %s", *allowClients)
	}
	if denyPrivateDestinations {
		log.Print("private destinations denied")
	}

	errCh := make(chan error, 2)

	if *socksAddr != "" {
		go func() {
			log.Printf("SOCKS5 proxy listening on %s", *socksAddr)
			errCh <- serveSOCKS5(*socksAddr, auth, allowlist)
		}()
	}

	if *httpAddr != "" {
		go func() {
			log.Printf("HTTP/HTTPS proxy listening on %s", *httpAddr)
			ln, err := listen(*httpAddr, allowlist)
			if err != nil {
				errCh <- err
				return
			}
			server := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handleHTTPProxy(w, r, auth)
				}),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       90 * time.Second,
			}
			errCh <- server.Serve(ln)
		}()
	}

	log.Fatal(<-errCh)
}

func serveSOCKS5(addr string, auth credentials, allowlist clientAllowlist) error {
	ln, err := listen(addr, allowlist)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			if err := handleSOCKS5(conn, auth); err != nil {
				log.Printf("SOCKS5 %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleSOCKS5(client net.Conn, auth credentials) error {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(client)

	if err := negotiateSOCKS5Authentication(reader, client, auth); err != nil {
		return err
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil {
		return err
	}
	if request[0] != 0x05 {
		return fmt.Errorf("invalid request version: %d", request[0])
	}
	command := request[1]
	if command != socksCmdConnect && command != socksCmdUDPAssociate {
		_ = writeSOCKSReply(client, 0x07, nil) // Command not supported
		return fmt.Errorf("unsupported command: %d", command)
	}

	host, err := readSOCKSAddress(reader, request[3])
	if err != nil {
		_ = writeSOCKSReply(client, 0x08, nil) // Address type not supported
		return err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBytes)

	if command == socksCmdUDPAssociate {
		// DST.ADDR/DST.PORT is only the client's expected source address,
		// which is unreliable behind NAT, so it is not used.
		return handleSOCKS5UDPAssociate(client, reader)
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	target, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		reply := byte(0x05) // Connection refused / general failure
		if errors.Is(err, errDestinationDenied) {
			reply = 0x02 // Connection not allowed by ruleset
		}
		_ = writeSOCKSReply(client, reply, nil)
		return fmt.Errorf("dial %s: %w", targetAddr, err)
	}
	defer target.Close()

	if err := writeSOCKSReply(client, 0x00, target.LocalAddr()); err != nil {
		return err
	}

	_ = client.SetDeadline(time.Time{})
	log.Printf("SOCKS5 %s -> %s", client.RemoteAddr(), targetAddr)
	relay(client, target)
	return nil
}

func readSOCKSAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03: // Domain
		length := []byte{0}
		if _, err := io.ReadFull(r, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func writeSOCKSReply(conn net.Conn, reply byte, bindAddr net.Addr) error {
	ip := net.IPv4zero
	port := 0

	switch addr := bindAddr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
		port = addr.Port
	case *net.UDPAddr:
		ip = addr.IP
		port = addr.Port
	}

	var response []byte
	if ip4 := ip.To4(); ip4 != nil {
		response = []byte{0x05, reply, 0x00, 0x01}
		response = append(response, ip4...)
	} else {
		response = []byte{0x05, reply, 0x00, 0x04}
		response = append(response, ip.To16()...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	response = append(response, portBytes...)
	_, err := conn.Write(response)
	return err
}

var transport = &http.Transport{
	Proxy:                 nil,
	DialContext:           dialer.DialContext,
	ForceAttemptHTTP2:     false,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, auth credentials) {
	if !authenticateHTTPProxy(w, r, auth) {
		return
	}

	if r.Method == http.MethodConnect {
		handleConnect(w, r)
		return
	}

	// A proxy request carries an absolute URL. Forwarding an origin-form
	// request to r.Host would send it back to this proxy in a loop.
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "not a proxy request: absolute URL required", http.StatusBadRequest)
		return
	}

	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	removeHopByHopHeaders(outReq.Header)
	outReq.Host = r.Host

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "proxy error: "+err.Error(), dialErrorStatus(err))
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	log.Printf("HTTP %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := r.Host
	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		targetAddr = net.JoinHostPort(targetAddr, "443")
	}

	target, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, "connect error: "+err.Error(), dialErrorStatus(err))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		http.Error(w, "hijack error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()
	defer target.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Normally CONNECT has no buffered body, but preserve any bytes already read.
	if buffered.Reader.Buffered() > 0 {
		_, _ = io.CopyN(target, buffered, int64(buffered.Reader.Buffered()))
	}

	log.Printf("CONNECT %s -> %s", client.RemoteAddr(), targetAddr)
	relay(client, target)
}

func dialErrorStatus(err error) int {
	if errors.Is(err, errDestinationDenied) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func relay(a, b net.Conn) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)

	copyConn := func(dst, src net.Conn) {
		if err := copyUntilIdle(dst, src, &lastActivity); err != nil {
			// Idle timeout or broken connection: tear down both directions.
			_ = a.Close()
			_ = b.Close()
		} else if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}

	go copyConn(a, b)
	go copyConn(b, a)
	<-done
	<-done
}

// copyUntilIdle copies src to dst until EOF. It fails once neither direction
// of the tunnel, tracked by lastActivity, has carried data for idleTimeout.
func copyUntilIdle(dst, src net.Conn, lastActivity *atomic.Int64) error {
	if idleTimeout <= 0 {
		_, err := io.Copy(dst, src)
		return err
	}

	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			lastActivity.Store(time.Now().UnixNano())
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, os.ErrDeadlineExceeded) && idleSince(lastActivity) < idleTimeout:
			// The other direction is still active.
		default:
			return err
		}
	}
}

func idleSince(lastActivity *atomic.Int64) time.Duration {
	return time.Since(time.Unix(0, lastActivity.Load()))
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	// RFC 7230: headers named by Connection are hop-by-hop too.
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}

	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}
