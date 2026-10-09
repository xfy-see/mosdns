//go:build !mosdns_minimal

/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/transport"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const tlsHandshakeTimeout = time.Second * 3

// Keep encrypted transports out of the minimal resolver's link graph.
func newEncryptedUpstream(addrURL *url.URL, opt Opt,
	newTcpDialer func(bool, uint16) (func(context.Context) (net.Conn, error), error),
	newUdpAddrResolveFunc func(uint16) (func(context.Context) (*net.UDPAddr, error), error),
) (Upstream, error) {
	addrUrlHost := tryTrimIpv6Brackets(addrURL.Host)
	switch addrURL.Scheme {
	case "tls":
		const defaultPort = 853
		tlsConfig := opt.TLSConfig.Clone()
		if tlsConfig == nil {
			tlsConfig = new(tls.Config)
		}
		if len(tlsConfig.ServerName) == 0 {
			tlsConfig.ServerName = tryRemovePort(addrUrlHost)
		}

		tcpDialer, err := newTcpDialer(false, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("failed to init tcp dialer, %w", err)
		}

		dialNetConn := func(ctx context.Context) (transport.NetConn, error) {
			conn, err := tcpDialer(ctx)
			if err != nil {
				return nil, err
			}
			conn = wrapConn(conn, opt.EventObserver)
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tlsConn.Close()
				return nil, err
			}
			return wrapConn(tlsConn, opt.EventObserver), nil
		}

		if opt.EnablePipeline {
			to := transport.TraditionalDnsConnOpts{
				WithLengthHeader:   true,
				IdleTimeout:        opt.IdleTimeout,
				MaxConcurrentQuery: pipelineConcurrentLimit,
			}
			dialDnsConn := func(ctx context.Context) (transport.DnsConn, error) {
				c, err := dialNetConn(ctx)
				if err != nil {
					return nil, err
				}
				return transport.NewDnsConn(to, c), nil
			}
			return transport.NewPipelineTransport(transport.PipelineOpts{
				DialContext:                    dialDnsConn,
				MaxConcurrentQueryWhileDialing: pipelineConcurrentLimit,
				Logger:                         opt.Logger,
			}), nil
		}
		return transport.NewReuseConnTransport(transport.ReuseConnOpts{DialContext: dialNetConn}), nil
	case "https":
		const defaultPort = 443

		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}

		var t http.RoundTripper
		var addonCloser io.Closer
		if opt.EnableHTTP3 {
			udpBootstrap, err := newUdpAddrResolveFunc(defaultPort)
			if err != nil {
				return nil, fmt.Errorf("failed to init udp addr bootstrap, %w", err)
			}

			lc := net.ListenConfig{Control: getSocketControlFunc(socketOpts{so_mark: opt.SoMark, bind_to_device: opt.BindToDevice})}
			conn, err := lc.ListenPacket(context.Background(), "udp", "")
			if err != nil {
				return nil, fmt.Errorf("failed to init udp socket for quic, %w", err)
			}
			quicTransport := &quic.Transport{Conn: conn}
			addonCloser = &ownedQUICSocket{transport: quicTransport, conn: conn}
			quicConfig := newDefaultClientQuicConfig()
			quicConfig.MaxIdleTimeout = idleConnTimeout

			t = &http3.Transport{
				TLSClientConfig: opt.TLSConfig,
				QUICConfig:      quicConfig,
				Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					ua, err := udpBootstrap(ctx)
					if err != nil {
						return nil, err
					}
					return quicTransport.DialEarly(ctx, ua, tlsCfg, cfg)
				},
				MaxResponseHeaderBytes: 4 * 1024,
			}
		} else {
			tcpDialer, err := newTcpDialer(false, defaultPort)
			if err != nil {
				return nil, fmt.Errorf("failed to init tcp dialer, %w", err)
			}
			owned := new(ownedHTTPConns)
			addonCloser = owned
			t1 := &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) { // overwrite server addr
					c, err := tcpDialer(ctx)
					if err != nil {
						return nil, err
					}
					return owned.wrap(wrapConn(c, opt.EventObserver))
				},
				TLSClientConfig:     opt.TLSConfig,
				TLSHandshakeTimeout: tlsHandshakeTimeout,
				IdleConnTimeout:     idleConnTimeout,
				ForceAttemptHTTP2:   true, // Custom DialContext/TLSClientConfig must still negotiate h2.
				// net/http adds 10*32 bytes of HTTP/2 per-field overhead to
				// this value. Keep the existing 4 KiB HTTP/2 header-list cap;
				// HTTP/1 responses now share the 3776-byte wire cap.
				MaxResponseHeaderBytes: 4*1024 - 10*32,
				HTTP2: &http.HTTP2Config{
					MaxReadFrameSize: 16 * 1024,
					SendPingTimeout:  time.Second * 30,
					PingTimeout:      time.Second * 5,
				},

				// Following opts are for http/1 only.
				// MaxConnsPerHost:     2,
				// MaxIdleConnsPerHost: 2,
			}

			t = t1
		}

		return newDoHWithOwnedTransport(addrURL.String(), t, addonCloser, opt.Logger)

	case "quic", "doq":
		const defaultPort = 853
		tlsConfig := opt.TLSConfig.Clone()
		if tlsConfig == nil {
			tlsConfig = new(tls.Config)
		}
		if len(tlsConfig.ServerName) == 0 {
			tlsConfig.ServerName = tryRemovePort(addrUrlHost)
		}
		tlsConfig.NextProtos = []string{"doq"}

		quicConfig := newDefaultClientQuicConfig()
		if opt.IdleTimeout > 0 {
			quicConfig.MaxIdleTimeout = opt.IdleTimeout
		}
		// Don't accept stream.
		quicConfig.MaxIncomingStreams = -1
		quicConfig.MaxIncomingUniStreams = -1

		udpBootstrap, err := newUdpAddrResolveFunc(defaultPort)
		if err != nil {
			return nil, fmt.Errorf("failed to init udp addr bootstrap, %w", err)
		}

		srk, _, err := utils.InitQUICSrkFromIfaceMac()
		if err != nil {
			opt.Logger.Warn("failed to init quic stateless reset key, it will be disabled", zap.Error(err))
		}

		lc := net.ListenConfig{Control: getSocketControlFunc(socketOpts{so_mark: opt.SoMark, bind_to_device: opt.BindToDevice})}
		uc, err := lc.ListenPacket(context.Background(), "udp", "")
		if err != nil {
			return nil, fmt.Errorf("failed to init udp socket for quic, %w", err)
		}

		t := &quic.Transport{
			Conn:              uc,
			StatelessResetKey: (*quic.StatelessResetKey)(srk),
		}

		dialDnsConn := func(ctx context.Context) (transport.DnsConn, error) {
			ua, err := udpBootstrap(ctx)
			if err != nil {
				return nil, fmt.Errorf("bootstrap failed, %w", err)
			}

			// This is a workaround to
			// 1. recover from strange 0rtt rejected err.
			// 2. avoid NextConnection might block forever.
			// TODO: Remove this workaround.
			var c *quic.Conn
			ec, err := t.DialEarly(ctx, ua, tlsConfig, quicConfig)
			if err != nil {
				return nil, err
			}
			c, err = ec.NextConnection(ctx)
			if err != nil {
				_ = ec.CloseWithError(0, "upstream dial failed")
				return nil, err
			}
			return transport.NewQuicDnsConn(c), nil
		}

		u := transport.NewPipelineTransport(transport.PipelineOpts{
			DialContext: dialDnsConn,
			// Quic rfc recommendation is 100. Some implications use 65535.
			MaxConcurrentQueryWhileDialing: 90,
			Logger:                         opt.Logger,
		})
		return &upstreamWithOwnedCloser{
			Upstream: u,
			closer:   &ownedQUICSocket{transport: t, conn: uc},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol [%s]", addrURL.Scheme)
	}
}

func newDefaultClientQuicConfig() *quic.Config {
	return &quic.Config{
		TokenStore: quic.NewLRUTokenStore(4, 8),

		// Dns does not need large amount of io, so the rx/tx windows are small.
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024,

		MaxIdleTimeout:       time.Second * 30,
		KeepAlivePeriod:      time.Second * 25,
		HandshakeIdleTimeout: tlsHandshakeTimeout,
	}
}

func checkProfileOptions(_ string, _ Opt) error { return nil }
