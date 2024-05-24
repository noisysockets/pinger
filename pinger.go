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
	"time"
)

// Pinger is a simple wrapper around the ping command.
type Pinger struct{}

// New creates a new Pinger.
func New() *Pinger {
	return &Pinger{}
}

// Ping sends a single ICMP echo request to the target host.
// Network is used to specify the IP version to use, valid values
// are "ip", "ip4" and "ip6".
func (p *Pinger) Ping(ctx context.Context, network, host string) error {
	// Don't hang forever.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var args []string
	if runtime.GOOS == "windows" {
		if network == "ip4" {
			args = append(args, "/4")
		} else if network == "ip6" {
			args = append(args, "/6")
		}

		args = append(args, "/n", "1")
	} else {
		if network == "ip4" {
			args = append(args, "-4")
		} else if network == "ip6" {
			args = append(args, "-6")
		}

		args = append(args, "-c", "1")
	}

	cmd := exec.CommandContext(ctx, "ping", append(args, host)...)
	if _, err := cmd.CombinedOutput(); err != nil {
		// TODO: parse the command output to get more information.
		return err
	}

	return nil
}
