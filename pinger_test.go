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

	"github.com/noisysockets/pinger"
	"github.com/stretchr/testify/require"
)

func TestPinger(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		p := pinger.New()

		ctx := context.Background()
		err := p.Ping(ctx, "ip4", "127.0.0.1")
		require.NoError(t, err)
	})

	t.Run("IPv6", func(t *testing.T) {
		p := pinger.New()

		ctx := context.Background()
		err := p.Ping(ctx, "ip6", "::1")
		require.NoError(t, err)
	})
}
