package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	socksCmdConnect      = byte(0x01)
	socksCmdUDPAssociate = byte(0x03)

	maxUDPPacketSize = 64 * 1024
)

// udpAssociation relays datagrams for one SOCKS5 UDP ASSOCIATE request.
// clientConn talks to the SOCKS client, targetConn talks to remote hosts.
type udpAssociation struct {
	clientConn *net.UDPConn
	targetConn *net.UDPConn
	clientIP   netip.Addr

	lastActivity atomic.Int64 // UnixNano of the last datagram in either direction

	mu         sync.Mutex
	clientAddr netip.AddrPort              // locked to the first valid client datagram
	targets    map[netip.AddrPort]struct{} // remotes the client has sent to
}

func handleSOCKS5UDPAssociate(client net.Conn, control *bufio.Reader) error {
	clientTCP, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = writeSOCKSReply(client, 0x01, nil)
		return errors.New("UDP ASSOCIATE requires a TCP control connection")
	}
	localTCP, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = writeSOCKSReply(client, 0x01, nil)
		return errors.New("UDP ASSOCIATE requires a TCP control connection")
	}
	clientIP, ok := netip.AddrFromSlice(clientTCP.IP)
	if !ok {
		_ = writeSOCKSReply(client, 0x01, nil)
		return fmt.Errorf("invalid client address: %s", clientTCP.IP)
	}

	// Bind on the same local IP the client reached us on, so the address in
	// the reply is one the client can actually send to.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localTCP.IP})
	if err != nil {
		_ = writeSOCKSReply(client, 0x01, nil) // General failure
		return fmt.Errorf("listen UDP relay: %w", err)
	}
	defer clientConn.Close()

	targetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = writeSOCKSReply(client, 0x01, nil)
		return fmt.Errorf("listen UDP outbound: %w", err)
	}
	defer targetConn.Close()

	if err := writeSOCKSReply(client, 0x00, clientConn.LocalAddr()); err != nil {
		return err
	}

	_ = client.SetDeadline(time.Time{})
	log.Printf("SOCKS5 UDP %s associated on %s", client.RemoteAddr(), clientConn.LocalAddr())

	assoc := &udpAssociation{
		clientConn: clientConn,
		targetConn: targetConn,
		clientIP:   clientIP.Unmap(),
		targets:    make(map[netip.AddrPort]struct{}),
	}
	assoc.lastActivity.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assoc.relayFromClient()
	}()
	go func() {
		defer wg.Done()
		assoc.relayFromTargets()
	}()

	// RFC 1928: the association ends when the TCP control connection closes.
	assoc.waitForControlClose(client, control)
	clientConn.Close()
	targetConn.Close()
	wg.Wait()
	log.Printf("SOCKS5 UDP %s association closed", client.RemoteAddr())
	return nil
}

// waitForControlClose blocks until the control connection closes, or until
// no datagram has been relayed for idleTimeout.
func (a *udpAssociation) waitForControlClose(client net.Conn, control *bufio.Reader) {
	if idleTimeout <= 0 {
		_, _ = io.Copy(io.Discard, control)
		return
	}

	buf := make([]byte, 512)
	for {
		_ = client.SetReadDeadline(time.Now().Add(idleTimeout))
		_, err := control.Read(buf)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded) && idleSince(&a.lastActivity) < idleTimeout:
		default:
			return
		}
	}
}

func (a *udpAssociation) relayFromClient() {
	buf := make([]byte, maxUDPPacketSize)
	for {
		n, from, err := a.clientConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = unmapAddrPort(from)
		if !a.acceptClient(from) {
			continue
		}

		target, payload, err := parseSOCKSUDPDatagram(buf[:n])
		if err != nil {
			log.Printf("SOCKS5 UDP %s: %v", from, err)
			continue
		}
		targetAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			log.Printf("SOCKS5 UDP %s: resolve %s: %v", from, target, err)
			continue
		}
		dst := unmapAddrPort(targetAddr.AddrPort())
		if err := checkDestination(dst.Addr()); err != nil {
			log.Printf("SOCKS5 UDP %s: %v", from, err)
			continue
		}
		a.lastActivity.Store(time.Now().UnixNano())

		a.mu.Lock()
		a.targets[dst] = struct{}{}
		a.mu.Unlock()

		_, _ = a.targetConn.WriteToUDPAddrPort(payload, dst)
	}
}

func (a *udpAssociation) relayFromTargets() {
	buf := make([]byte, maxUDPPacketSize)
	for {
		n, from, err := a.targetConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = unmapAddrPort(from)

		a.mu.Lock()
		_, known := a.targets[from]
		clientAddr := a.clientAddr
		a.mu.Unlock()
		// Drop unsolicited datagrams from hosts the client never contacted.
		if !known || !clientAddr.IsValid() {
			continue
		}

		a.lastActivity.Store(time.Now().UnixNano())

		datagram := appendSOCKSUDPHeader(make([]byte, 0, n+22), from)
		datagram = append(datagram, buf[:n]...)
		_, _ = a.clientConn.WriteToUDPAddrPort(datagram, clientAddr)
	}
}

// acceptClient reports whether a datagram from addr belongs to this
// association: it must come from the control connection's IP, and from the
// same port as the first datagram seen.
func (a *udpAssociation) acceptClient(addr netip.AddrPort) bool {
	if addr.Addr() != a.clientIP {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.clientAddr.IsValid() {
		a.clientAddr = addr
	}
	return a.clientAddr == addr
}

// parseSOCKSUDPDatagram splits a client datagram into its destination and
// payload. Request: RSV(2), FRAG, ATYP, DST.ADDR, DST.PORT, DATA
func parseSOCKSUDPDatagram(datagram []byte) (target string, payload []byte, err error) {
	if len(datagram) < 4 {
		return "", nil, errors.New("short UDP datagram")
	}
	if datagram[2] != 0x00 {
		return "", nil, fmt.Errorf("UDP fragmentation not supported (frag=%d)", datagram[2])
	}

	r := bytes.NewReader(datagram[4:])
	host, err := readSOCKSAddress(r, datagram[3])
	if err != nil {
		return "", nil, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", nil, errors.New("short UDP datagram")
	}
	port := binary.BigEndian.Uint16(portBytes)

	payload = datagram[len(datagram)-r.Len():]
	return net.JoinHostPort(host, strconv.Itoa(int(port))), payload, nil
}

func appendSOCKSUDPHeader(buf []byte, from netip.AddrPort) []byte {
	buf = append(buf, 0x00, 0x00, 0x00) // RSV, FRAG
	if from.Addr().Is4() {
		buf = append(buf, 0x01)
	} else {
		buf = append(buf, 0x04)
	}
	buf = append(buf, from.Addr().AsSlice()...)
	return binary.BigEndian.AppendUint16(buf, from.Port())
}

func unmapAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}
