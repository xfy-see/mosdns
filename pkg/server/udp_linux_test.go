//go:build linux

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUDPWildcardReplyUsesDestinationAddress(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	h := handlerFunc(func(_ context.Context, q *dns.Msg, meta QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		if !meta.FromUDP || !meta.ClientAddr.IsLoopback() {
			t.Error("wrong UDP metadata")
		}
		r := new(dns.Msg)
		r.SetReply(q)
		b, err := pack(r)
		if err != nil {
			t.Error(err)
		}
		return b
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServeUDP(serverConn, h, UDPServerOpts{}) }()
	defer func() {
		serverConn.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// A wildcard IPv4 socket must echo the address that received each query,
	// rather than let the route choose 127.0.0.1 for both responses.
	for _, destination := range []net.IP{net.IPv4(127, 0, 0, 2), net.IPv4(127, 0, 0, 3)} {
		to := &net.UDPAddr{IP: destination, Port: serverConn.LocalAddr().(*net.UDPAddr).Port}
		if _, err := clientConn.WriteToUDP(wire, to); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, dns.MaxMsgSize)
		n, from, err := clientConn.ReadFromUDP(response)
		if err != nil {
			t.Fatal(err)
		}
		if !from.IP.Equal(destination) {
			t.Fatalf("response source %s differs from original query destination %s", from.IP, destination)
		}
		var r dns.Msg
		if err := r.Unpack(response[:n]); err != nil || !r.Response || r.Id != q.Id {
			t.Fatalf("invalid response: %v", err)
		}
	}
}
