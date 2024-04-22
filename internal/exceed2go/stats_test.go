// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go_test

import (
	"net/netip"
	"testing"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadStats(t *testing.T) {
	attachOpts := exceed2go.AttachOptions{
		IfaceIndex: 1,
		HopList: exceed2go.HopList{
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("fe80::2"),
		},
		Mode:  exceed2go.ModeTC,
		Layer: exceed2go.Layer3,
	}

	t.Cleanup(exceed2go.RemoveAll)
	require.NoError(t, exceed2go.Attach(attachOpts), "Attach")

	stats, err := exceed2go.ReadStats(1)
	require.NoError(t, err, "ReadStats")
	assert.NotNil(t, stats)
}
