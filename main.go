package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var dialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address; empty disables it")
	httpAddr := flag.String("http", "127.0.0.1:8080", "HTTP/HTTPS proxy listen address; empty disables it")
	authUser := flag.String("auth-user", "", "proxy authentication username (or SIMPLE_PROXY_USER)")
	authPassword := flag.String("auth-password", "", "proxy authentication password (or SIMPLE_PROXY_PASSWORD)")
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

	errCh := make(chan error, 2)

	if *socksAddr != "" {
		go func() {
			log.Printf("SOCKS5 proxy listening on %s", *socksAddr)
			errCh <- serveSOCKS5(*socksAddr, auth)
		}()
	}

	if *httpAddr != "" {
		go func() {
			log.Printf("HTTP/HTTPS proxy listening on %s", *httpAddr)
			server := &http.Server{
				Addr: *httpAddr,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handleHTTPProxy(w, r, auth)
				}),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       90 * time.Second,
			}
			errCh <- server.ListenAndServe()
		}()
	}

	log.Fatal(<-errCh)
}

func serveSOCKS5(addr string, auth credentials) error {
	ln, err := net.Listen("tcp", addr)
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
	if request[1] != 0x01 {
		_ = writeSOCKSReply(client, 0x07, nil) // Command not supported
		return fmt.Errorf("unsupported command: %d", request[1])
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
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	target, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		_ = writeSOCKSReply(client, 0x05, nil) // Connection refused / general failure
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

	if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
		ip = tcpAddr.IP
		port = tcpAddr.Port
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

	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	removeHopByHopHeaders(outReq.Header)

	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	outReq.Host = r.Host

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
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
		http.Error(w, "connect error: "+err.Error(), http.StatusBadGateway)
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

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)

	copyConn := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}

	go copyConn(a, b)
	go copyConn(b, a)
	<-done
	<-done
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
