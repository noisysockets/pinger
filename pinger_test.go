// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package pinger_test

import (
	"context"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/pinger"
	"github.com/stretchr/testify/require"
)

func TestPinger(t *testing.T) {
	logger := slogt.New(t)

	p := pinger.New(
		pinger.WithLogger(logger),
	)

	t.Run("IP", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Ping(ctx, "ip", "google.com")
		require.NoError(t, err)
	})

	t.Run("IPv4", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Ping(ctx, "ip4", "127.0.0.1")
		require.NoError(t, err)
	})

	t.Run("IPv6", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Ping(ctx, "ip6", "::1")
		require.NoError(t, err)
	})
}
