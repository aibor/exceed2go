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

func TestParseHopList(t *testing.T) {
	tests := []struct {
		name    string
		invalid bool
		input   []string
	}{
		{
			name:  "empty",
			input: []string{},
		},
		{
			name:  "one valid",
			input: []string{"fe80::1"},
		},
		{
			name: "many valid",
			input: []string{
				"fe80::1",
				"fe80::2",
				"fe80::3",
				"fe80::4",
			},
		},
		{
			name:    "one invalid",
			invalid: true,
			input:   []string{"fe80::g"},
		},

		{
			name:    "one invalid in many",
			invalid: true,
			input: []string{
				"fe80::1",
				"fe80::2",
				"1.2.3.4",
				"fe80::4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := exceed2go.ParseHopList(tt.input)
			if tt.invalid {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			expected := make(exceed2go.HopList, len(tt.input))
			for idx, addr := range tt.input {
				expected[idx] = netip.MustParseAddr(addr)
			}

			assert.ElementsMatch(t, expected, actual)
		})
	}
}

func TestParseHop(t *testing.T) {
	tests := []struct {
		name    string
		invalid bool
		input   string
	}{
		{
			name:  "valid IPv6",
			input: "fe80::1",
		},
		{
			name:    "invalid IPv6",
			invalid: true,
			input:   "fe80::g",
		},
		{
			name:    "valid IPv4",
			invalid: true,
			input:   "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := exceed2go.ParseHop(tt.input)
			if tt.invalid {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			expected := netip.MustParseAddr(tt.input)
			assert.Equal(t, expected, actual)
		})
	}
}
