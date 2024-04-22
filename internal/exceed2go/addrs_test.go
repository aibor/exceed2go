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

func TestReadAddrs(t *testing.T) {
	hopList := exceed2go.HopList{
		netip.MustParseAddr("fd01::1"),
		netip.MustParseAddr("fd01::2"),
		netip.MustParseAddr("fd01::3"),
	}

	attachOpts := exceed2go.AttachOptions{
		IfaceIndex: 1,
		HopList:    hopList,
		Mode:       exceed2go.ModeTC,
		Layer:      exceed2go.Layer3,
	}

	t.Cleanup(exceed2go.RemoveAll)
	require.NoError(t, exceed2go.Attach(attachOpts), "Attach")

	actual, err := exceed2go.ReadAddrs(1)
	require.NoError(t, err, "ReadAddrs")

	assert.ElementsMatch(t, hopList, actual, "hopLists should be equal")
}
