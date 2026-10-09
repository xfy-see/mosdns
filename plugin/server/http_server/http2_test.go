//go:build !mosdns_minimal

package tcp_server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func httpServerTLSFixture(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config = newHTTPServer(handler, &Args{IdleTimeout: 3})
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func httpServerTLSConfig(s *httptest.Server) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return &tls.Config{RootCAs: roots}
}

func TestHTTPServerTLSHTTP2AndHTTP1(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		t.Run(fmt.Sprintf("http2=%v", h2), func(t *testing.T) {
			type observation struct {
				proto int
				alpn  string
				body  []byte
				err   error
			}
			seen := make(chan observation, 1)
			s := httpServerTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				seen <- observation{r.ProtoMajor, r.TLS.NegotiatedProtocol, body, err}
				_, _ = w.Write(body)
			}))
			tlsConfig := httpServerTLSConfig(s)
			if !h2 {
				tlsConfig.NextProtos = []string{"http/1.1"}
			}
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetHTTP2(h2)
			tr := &http.Transport{TLSClientConfig: tlsConfig, Protocols: protocols}
			if !h2 {
				// The standard Transport suppresses ALPN when HTTP/1-only.
				// Explicitly offer http/1.1 to verify the server's ALPN fallback.
				tr.DialTLSContext = (&tls.Dialer{Config: tlsConfig}).DialContext
			}
			t.Cleanup(tr.CloseIdleConnections)
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			// Larger than either 65535-byte receive window: completing the POST
			// requires the configured HTTP/2 flow control to replenish credit.
			body := bytes.Repeat([]byte("flow-control"), 12*1024)
			resp, err := client.Post(s.URL, "application/octet-stream", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || !bytes.Equal(reply, body) {
				t.Fatalf("POST body changed: len=%d err=%v", len(reply), err)
			}
			got := <-seen
			wantProto, wantALPN := 1, "http/1.1"
			if h2 {
				wantProto, wantALPN = 2, "h2"
			}
			if got.proto != wantProto || got.alpn != wantALPN || got.err != nil || !bytes.Equal(got.body, body) {
				t.Fatalf("server TLS/ALPN/body changed: proto=%d alpn=%s bytes=%d err=%v", got.proto, got.alpn, len(got.body), got.err)
			}
		})
	}
}

func TestHTTPServerHTTP2AdvertisesLimits(t *testing.T) {
	s := httpServerTLSFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := httpServerTLSConfig(s)
	tlsConfig.NextProtos = []string{"h2"}
	conn, err := tls.Dial("tcp", s.Listener.Addr().String(), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("server did not negotiate h2")
	}
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var frame [9]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		t.Fatal(err)
	}
	length := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	if frame[3] != 4 || frame[4] != 0 || binary.BigEndian.Uint32(frame[5:]) != 0 || length%6 != 0 || length > 1024 {
		t.Fatal("invalid initial server SETTINGS frame")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	settings := make(map[uint16]uint32)
	for offset := 0; offset < length; offset += 6 {
		settings[binary.BigEndian.Uint16(payload[offset:])] = binary.BigEndian.Uint32(payload[offset+2:])
	}
	if settings[4] != 65535 || settings[5] != 16*1024 || settings[6] != 512+10*32 {
		t.Fatalf("server HTTP/2 wire limits changed: %v", settings)
	}
}

func TestHTTPServerPlainHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.TLS != nil {
			t.Errorf("plain HTTP changed: proto=%s TLS=%v", r.Proto, r.TLS)
		}
		_, _ = io.WriteString(w, "plain HTTP")
	})
	s := httptest.NewUnstartedServer(handler)
	s.Config = newHTTPServer(handler, &Args{IdleTimeout: 3})
	s.Start()
	defer s.Close()
	resp, err := s.Client().Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "plain HTTP" {
		t.Fatalf("plain HTTP failed: body=%q err=%v", body, err)
	}
}
