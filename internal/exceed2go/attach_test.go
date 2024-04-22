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

func TestAttach(t *testing.T) {
	tests := []struct {
		name string
		opts exceed2go.AttachOptions
		err  error
	}{
		{
			name: "empty opts",
			err:  exceed2go.ErrInvalidInterface,
		},
		{
			name: "invalid interface",
			opts: exceed2go.AttachOptions{
				HopList: exceed2go.HopList{
					netip.MustParseAddr("fd01::1"),
				},
			},
			err: exceed2go.ErrInvalidInterface,
		},
		{
			name: "no hops",
			opts: exceed2go.AttachOptions{
				IfaceIndex: 1,
			},
			err: exceed2go.ErrEmptyHopList,
		},
		{
			name: "invalid mode",
			opts: exceed2go.AttachOptions{
				IfaceIndex: 1,
				Mode:       4711,
				HopList: exceed2go.HopList{
					netip.MustParseAddr("fd01::1"),
				},
			},
			err: exceed2go.ErrUnknownMode,
		},
		{
			name: "invalid layer",
			opts: exceed2go.AttachOptions{
				IfaceIndex: 1,
				Layer:      4711,
				HopList: exceed2go.HopList{
					netip.MustParseAddr("fd01::1"),
				},
			},
			err: exceed2go.ErrUnknownLayer,
		},
		{
			name: "valid",
			opts: exceed2go.AttachOptions{
				IfaceIndex: 1,
				Mode:       exceed2go.ModeTC,
				Layer:      exceed2go.Layer2,
				HopList: exceed2go.HopList{
					netip.MustParseAddr("fd01::1"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exceed2go.Attach(tt.opts)
			t.Cleanup(exceed2go.RemoveAll)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			assert.FileExists(t, "/sys/fs/bpf/exceed2go/1/link")
			assert.FileExists(t, "/sys/fs/bpf/exceed2go/1/exceed2go_addrs")
			assert.FileExists(t, "/sys/fs/bpf/exceed2go/1/exceed2go_counters")
		})
	}
}
