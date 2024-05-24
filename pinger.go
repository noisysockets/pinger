// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package pinger

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

// Pinger is a simple wrapper around the ping command.
type Pinger struct {
	host    string
	timeout time.Duration
}

type Option func(*Pinger)

// WithTimeout sets the timeout to wait for a ping response.
func WithTimeout(timeout time.Duration) Option {
	return func(p *Pinger) {
		p.timeout = timeout
	}
}

// New creates a new Pinger.
func New(host string, opts ...Option) *Pinger {
	p := &Pinger{
		host:    host,
		timeout: 5 * time.Second,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Ping sends a single ICMP echo request to the target host.
// Network is used to specify the IP version to use, valid values
// are "ip", "ip4" and "ip6".
func (p *Pinger) Ping(ctx context.Context, network string) error {
	var args []string
	if runtime.GOOS == "windows" {
		if network == "ip4" {
			args = append(args, "/4")
		} else if network == "ip6" {
			args = append(args, "/6")
		}

		args = append(args,
			"/n", "1",
			"/w", strconv.Itoa(int(p.timeout.Milliseconds())))
	} else {
		if network == "ip4" {
			args = append(args, "-4")
		} else if network == "ip6" {
			args = append(args, "-6")
		}

		args = append(args,
			"-c", "1",
			"-W", strconv.Itoa(int(p.timeout.Seconds())))
	}

	cmd := exec.CommandContext(ctx, "ping", append(args, p.host)...)
	if _, err := cmd.CombinedOutput(); err != nil {
		// TODO: parse the command output to get more information.
		return err
	}

	return nil
}
