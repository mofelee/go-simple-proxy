package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsPrivateDestination(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1":        true,
		"10.1.2.3":         true,
		"172.16.0.1":       true,
		"192.168.1.1":      true,
		"169.254.169.254":  true,
		"100.64.0.1":       true,
		"0.0.0.0":          true,
		"224.0.0.1":        true,
		"::1":              true,
		"fd00::1":          true,
		"fe80::1":          true,
		"::ffff:127.0.0.1": true,
		"8.8.8.8":          false,
		"2606:4700::1111":  false,
	}

	for addr, want := range tests {
		if got := isPrivateDestination(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPrivateDestination(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestClientAllowlist(t *testing.T) {
	allowlist, err := parseClientAllowlist("10.0.0.0/8, 192.168.1.5,::1")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]bool{
		"10.2.3.4":        true,
		"192.168.1.5":     true,
		"192.168.1.6":     false,
		"::1":             true,
		"::ffff:10.0.0.1": true,
		"8.8.8.8":         false,
	}
	for addr, want := range tests {
		tcpAddr := &net.TCPAddr{IP: net.ParseIP(addr), Port: 1234}
		if got := allowlist.allows(tcpAddr); got != want {
			t.Errorf("allows(%s) = %v, want %v", addr, got, want)
		}
	}

	if !clientAllowlist(nil).allows(&net.TCPAddr{IP: net.ParseIP("8.8.8.8")}) {
		t.Error("empty allowlist should allow every client")
	}
	if _, err := parseClientAllowlist("not-an-ip"); err == nil {
		t.Error("parseClientAllowlist() should reject invalid entries")
	}
}

func TestDenyPrivateSOCKS5Connect(t *testing.T) {
	setDenyPrivate(t)

	client, server := tcpPair(t)
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		_ = handleSOCKS5(server, credentials{})
	}()
	t.Cleanup(func() { <-handlerDone })

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	request := []byte{0x05, 0x01, socksNoAuthMethod, 0x05, socksCmdConnect, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[3] != 0x02 {
		t.Fatalf("CONNECT reply code = %d, want 2 (not allowed by ruleset)", reply[3])
	}
}

func TestDenyPrivateHTTPProxy(t *testing.T) {
	setDenyPrivate(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	recorder := httptest.NewRecorder()
	handleHTTPProxy(recorder, httptest.NewRequest(http.MethodGet, upstream.URL, nil), credentials{})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestHTTPProxyRejectsOriginFormRequest(t *testing.T) {
	recorder := httptest.NewRecorder()
	handleHTTPProxy(recorder, httptest.NewRequest(http.MethodGet, "/", nil), credentials{})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestRelayClosesIdleTunnel(t *testing.T) {
	setIdleTimeout(t, 100*time.Millisecond)

	clientA, relayA := tcpPair(t)
	relayB, clientB := tcpPair(t)
	done := make(chan struct{})
	go func() {
		relay(relayA, relayB)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close the idle tunnel")
	}

	_ = clientA.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientA.Read(make([]byte, 1)); err == nil {
		t.Fatal("client A should be closed after idle timeout")
	}
	_ = clientB.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientB.Read(make([]byte, 1)); err == nil {
		t.Fatal("client B should be closed after idle timeout")
	}
}

func TestRelayKeepsActiveTunnel(t *testing.T) {
	setIdleTimeout(t, 150*time.Millisecond)

	clientA, relayA := tcpPair(t)
	relayB, clientB := tcpPair(t)
	relayDone := make(chan struct{})
	go func() {
		relay(relayA, relayB)
		close(relayDone)
	}()
	// Runs before tcpPair's cleanups; the relay ends on its own once idle.
	t.Cleanup(func() { <-relayDone })

	// Traffic in one direction only must keep both directions open.
	buf := make([]byte, 1)
	for i := 0; i < 6; i++ {
		time.Sleep(75 * time.Millisecond)
		if _, err := clientA.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		_ = clientB.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(clientB, buf); err != nil {
			t.Fatalf("tunnel closed while active: %v", err)
		}
	}

	if _, err := clientB.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = clientA.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(clientA, buf); err != nil {
		t.Fatalf("reverse direction closed while tunnel active: %v", err)
	}
}

func setDenyPrivate(t *testing.T) {
	t.Helper()
	previous := denyPrivateDestinations
	denyPrivateDestinations = true
	t.Cleanup(func() { denyPrivateDestinations = previous })
}

func setIdleTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := idleTimeout
	idleTimeout = timeout
	t.Cleanup(func() { idleTimeout = previous })
}

// tcpPair returns two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		dialed.Close()
		server.Close()
	})
	return dialed, server
}
