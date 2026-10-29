package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

var errDestinationDenied = errors.New("destination not allowed")

// denyPrivateDestinations blocks proxying to loopback, private, link-local
// and other non-public addresses. Set from the -deny-private flag.
var denyPrivateDestinations bool

// cgnatPrefix is the RFC 6598 shared address space used by carrier NATs and
// VPNs such as Tailscale.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func isPrivateDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsUnspecified() || addr.IsMulticast() || cgnatPrefix.Contains(addr)
}

func checkDestination(addr netip.Addr) error {
	if denyPrivateDestinations && isPrivateDestination(addr) {
		return fmt.Errorf("%w: %s", errDestinationDenied, addr)
	}
	return nil
}

// dialControl runs after DNS resolution, so hostnames that resolve to a
// denied address are rejected too.
func dialControl(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	return checkDestination(addrPort.Addr())
}

type clientAllowlist []netip.Prefix

// parseClientAllowlist parses a comma-separated list of IPs and CIDRs.
// An empty list allows every client.
func parseClientAllowlist(value string) (clientAllowlist, error) {
	var allowlist clientAllowlist
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(field); err == nil {
			allowlist = append(allowlist, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return nil, fmt.Errorf("invalid client IP or CIDR %q", field)
		}
		addr = addr.Unmap()
		allowlist = append(allowlist, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return allowlist, nil
}

func (l clientAllowlist) allows(addr net.Addr) bool {
	if len(l) == 0 {
		return true
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range l {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// allowlistListener closes connections from clients not in the allowlist.
type allowlistListener struct {
	net.Listener
	allowlist clientAllowlist
}

func listen(addr string, allowlist clientAllowlist) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if len(allowlist) == 0 {
		return ln, nil
	}
	return allowlistListener{Listener: ln, allowlist: allowlist}, nil
}

func (l allowlistListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allowlist.allows(conn.RemoteAddr()) {
			return conn, nil
		}
		log.Printf("rejected client %s: not in allowlist", conn.RemoteAddr())
		conn.Close()
	}
}
