package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParseSOCKSUDPDatagram(t *testing.T) {
	tests := []struct {
		name        string
		datagram    []byte
		wantTarget  string
		wantPayload []byte
		wantErr     bool
	}{
		{
			name:        "IPv4",
			datagram:    []byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x35, 'h', 'i'},
			wantTarget:  "1.2.3.4:53",
			wantPayload: []byte("hi"),
		},
		{
			name:        "domain",
			datagram:    append([]byte{0, 0, 0, 0x03, 11}, append([]byte("example.com"), 0x01, 0xbb, 'x')...),
			wantTarget:  "example.com:443",
			wantPayload: []byte("x"),
		},
		{
			name:     "fragmented",
			datagram: []byte{0, 0, 1, 0x01, 1, 2, 3, 4, 0x00, 0x35},
			wantErr:  true,
		},
		{
			name:     "truncated",
			datagram: []byte{0, 0, 0, 0x01, 1, 2},
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, payload, err := parseSOCKSUDPDatagram(test.datagram)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseSOCKSUDPDatagram() error = %v, wantErr %v", err, test.wantErr)
			}
			if target != test.wantTarget || !bytes.Equal(payload, test.wantPayload) {
				t.Fatalf("got (%q, %q), want (%q, %q)", target, payload, test.wantTarget, test.wantPayload)
			}
		})
	}
}

func TestAppendSOCKSUDPHeader(t *testing.T) {
	got := appendSOCKSUDPHeader(nil, netip.MustParseAddrPort("1.2.3.4:53"))
	want := []byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x35}
	if !bytes.Equal(got, want) {
		t.Fatalf("header = %v, want %v", got, want)
	}
}

func TestSOCKS5UDPAssociateRelaysDatagrams(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = handleSOCKS5(conn, credentials{})
	}()

	control, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Closing the control connection must end the association.
	defer func() {
		control.Close()
		select {
		case <-handlerDone:
		case <-time.After(5 * time.Second):
			t.Error("UDP association did not end after control connection closed")
		}
	}()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := control.Write([]byte{0x05, 0x01, socksNoAuthMethod}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{0x05, socksCmdUDPAssociate, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatal(err)
	}
	if reply[3] != 0x00 || reply[5] != 0x01 {
		t.Fatalf("UDP ASSOCIATE reply = %v", reply)
	}
	relayAddr := &net.UDPAddr{
		IP:   net.IP(reply[6:10]),
		Port: int(binary.BigEndian.Uint16(reply[10:12])),
	}

	udpClient, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(5 * time.Second))

	echoAddr := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	header := appendSOCKSUDPHeader(nil, echoAddr)
	if _, err := udpClient.Write(append(header, "ping"...)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, err := udpClient.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := append(appendSOCKSUDPHeader(nil, echoAddr), "ping"...)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("relayed datagram = %v, want %v", buf[:n], want)
	}
}
