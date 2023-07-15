package exceed2go_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aibor/exceed2go/internal/exceed2go"
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			hopList, err := exceed2go.ParseHopList(tt.input)
			if tt.invalid {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			output := make(exceed2go.HopList, len(tt.input))
			for idx, addr := range tt.input {
				output[idx] = netip.MustParseAddr(addr)
			}
			assert.ElementsMatch(t, output, hopList)
		})
	}
}
