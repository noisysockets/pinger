// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from prometheus/pro-bing.
 *
 * The MIT License (MIT)
 *
 * Copyright 2022 The Prometheus Authors
 * Copyright 2016 Cameron Sparr and contributors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package pinger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/semaphore"

	"github.com/noisysockets/resolver"
)

// Option is a configuration function for Pinger.
type Option func(*Pinger)

// WithLogger provides a logger to use for logging.
func WithLogger(logger *slog.Logger) Option {
	return func(p *Pinger) {
		p.logger = logger
	}
}

// WithResolver provides a DNS Resolver to use for resolving hostnames.
func WithResolver(r resolver.Resolver) Option {
	return func(p *Pinger) {
		p.resolver = r
	}
}

// WithMaxChildProcesses sets the maximum number of ping commands that can be
// run concurrently. This helps avoid an easy DoS target.
func WithMaxChildProcesses(n int) Option {
	return func(p *Pinger) {
		p.childProcessCounter = *semaphore.NewWeighted(int64(n))
	}
}

// WithPacketConn provides a PacketConn to use for sending and receiving ICMP messages.
func WithPacketConn(pc net.PacketConn) Option {
	return func(p *Pinger) {
		p.pc = pc
	}
}

// Pinger sends ICMP echo requests to hosts.
type Pinger struct {
	logger              *slog.Logger
	resolver            resolver.Resolver
	childProcessCounter semaphore.Weighted
	pc                  net.PacketConn
	id                  int
	seq                 atomic.Uint32
}

// New creates a new Pinger.
func New(opts ...Option) *Pinger {
	p := &Pinger{
		logger:              slog.Default(),
		resolver:            net.DefaultResolver,
		childProcessCounter: *semaphore.NewWeighted(32),
		id:                  rand.Intn(math.MaxUint16),
	}
	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Ping sends an ICMP echo request to the specified host.
// Known networks are "ip", "ip4", and "ip6".
func (p *Pinger) Ping(ctx context.Context, network, host string) error {
	logger := p.logger.With(slog.String("network", network), slog.String("host", host))

	pc := p.pc
	if pc == nil {
		pcNetwork := "udp4"
		bindAddr := netip.IPv4Unspecified()
		if network == "ip6" {
			pcNetwork = "udp6"
			bindAddr = netip.IPv6Unspecified()
		}

		// Workaround for: https://github.com/prometheus-community/pro-bing/tree/main?tab=readme-ov-file#windows
		if runtime.GOOS == "windows" {
			pcNetwork = "ip4:icmp"
			if network == "ip6" {
				pcNetwork = "ip6:ipv6-icmp"
			}
		}

		// Attempt to create an unprivileged ICMP PacketConn.
		var err error
		pc, err = icmp.ListenPacket(pcNetwork, bindAddr.String())
		if err != nil {
			if !errors.Is(err, os.ErrPermission) {
				logger.Debug("Failed to create unprivileged ICMP PacketConn", slog.Any("error", err))
			}

			pc = nil
		} else {
			defer pc.Close()
		}
	}

	if pc != nil {
		logger.Debug("Using PacketConn for ICMP echo requests")

		localAddrStr := pc.LocalAddr().String()
		localAddr, err := netip.ParseAddr(localAddrStr)
		if err != nil {
			localAddrPort, err := netip.ParseAddrPort(localAddrStr)
			if err != nil {
				return fmt.Errorf("failed to parse local address: %w", err)
			}
			localAddr = localAddrPort.Addr()
		}

		if localAddr.Is4() {
			if network == "ip6" {
				return &net.AddrError{Err: "unsupported network", Addr: localAddr.String()}
			}
			network = "ip4"
		} else {
			if network == "ip4" {
				return &net.AddrError{Err: "unsupported network", Addr: localAddr.String()}
			}
			network = "ip6"
		}

		addrs, err := p.resolver.LookupNetIP(ctx, network, host)
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			return &net.DNSError{Err: resolver.ErrNoSuchHost.Error(), Name: host}
		}

		return p.pingWithConn(ctx, logger, pc, addrs[0].Unmap())
	} else {
		logger.Debug("Using ping command for ICMP echo requests")

		return p.pingWithCommand(ctx, logger, network, host)
	}
}

func (p *Pinger) pingWithConn(ctx context.Context, logger *slog.Logger, pc net.PacketConn, addr netip.Addr) error {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if addr.Is6() {
		typ = ipv6.ICMPTypeEchoRequest
	}

	seq := p.seq.Add(1)
	if seq > math.MaxUint16 {
		p.seq.CompareAndSwap(seq, 0)
		seq = p.seq.Add(1)
	}

	req := icmp.Message{
		Type: typ,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  int(seq),
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	reqBytes, err := req.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	var icmpAddr net.Addr = &net.UDPAddr{IP: net.IP(addr.AsSlice())}
	if runtime.GOOS == "windows" {
		icmpAddr = &net.IPAddr{IP: net.IP(addr.AsSlice())}
	}

	logger.Debug("Sending ICMP echo request", slog.Any("addr", icmpAddr.String()),
		slog.Int("id", p.id), slog.Int("seq", int(seq)))

	if _, err := pc.WriteTo(reqBytes, icmpAddr); err != nil {
		return fmt.Errorf("failed to send ICMP echo request: %w", err)
	}

	ipHeaderLen := ipv4.HeaderLen
	if addr.Is6() {
		ipHeaderLen = ipv6.HeaderLen
	}

	// Some platforms need a buffer big enough to include the IP headers.
	// Eg. https://github.com/golang/go/issues/47369.
	replyBytes := make([]byte, len(reqBytes)+ipHeaderLen)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Poll for a reply.
		if err := pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, addr, err := pc.ReadFrom(replyBytes)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}

			return fmt.Errorf("failed to read ICMP echo reply: %w", err)
		}

		logger := logger.With(slog.String("addr", addr.String()))

		logger.Debug("Received ICMP message")

		reply, err := icmp.ParseMessage(typ.Protocol(), replyBytes[:n])
		if err != nil {
			return fmt.Errorf("failed to parse ICMP echo reply: %w", err)
		}

		// TODO: handle ICMP errors.

		if reply.Type != ipv4.ICMPTypeEchoReply && reply.Type != ipv6.ICMPTypeEchoReply {
			logger.Debug("Received ICMP message with unexpected type", slog.Any("type", reply.Type))
			continue
		}

		logger.Debug("Received ICMP echo reply")

		replyEcho := reply.Body.(*icmp.Echo)

		// Confirm that the reply is for our request.
		if replyEcho.Seq == int(seq) {
			break
		}

		logger.Debug("Received ICMP echo reply with unexpected sequence number",
			slog.Any("seq", replyEcho.Seq))
	}

	return nil
}

func (p *Pinger) pingWithCommand(ctx context.Context, logger *slog.Logger, network, host string) error {
	if err := p.childProcessCounter.Acquire(ctx, 1); err != nil {
		return fmt.Errorf("too many requests: %w", err)
	}
	defer p.childProcessCounter.Release(1)

	name := "ping"
	var args []string

	switch runtime.GOOS {
	case "windows":
		if network == "ip4" {
			args = append(args, "/4")
		} else if network == "ip6" {
			args = append(args, "/6")
		}

		args = append(args, "/n", "1")
	default:
		if network == "ip6" {
			name = "ping6"
		}

		args = append(args, "-c", "1")
	}

	logger.Debug("Executing ping command", slog.String("name", name))

	cmd := exec.CommandContext(ctx, name, append(args, host)...)
	if _, err := cmd.CombinedOutput(); err != nil {
		// TODO: parse the command output to get more information.
		return err
	}

	return nil
}
