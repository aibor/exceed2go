package ifinfo_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aibor/exceed2go/internal/ifinfo"
)

func TestIfUpNameList(t *testing.T) {
	tests := []struct {
		name   string
		input  []net.Interface
		output []string
	}{
		{
			name:   "empty",
			input:  []net.Interface{},
			output: []string{},
		},
		{
			name: "one up",
			input: []net.Interface{
				{
					Name:  "test0",
					Flags: net.FlagUp,
				},
			},
			output: []string{
				"test0",
			},
		},
		{
			name: "one down",
			input: []net.Interface{
				{
					Name: "test0",
				},
			},
			output: []string{},
		},
		{
			name: "only loopback up",
			input: []net.Interface{
				{
					Name:  "test0",
					Flags: net.FlagUp | net.FlagLoopback,
				},
			},
			output: []string{},
		},
		{
			name: "mixed",
			input: []net.Interface{
				{
					Name:  "test0",
					Flags: net.FlagUp,
				},
				{
					Name:  "test1",
					Flags: net.FlagUp | net.FlagLoopback,
				},
				{
					Name: "test2",
				},
				{
					Name:  "test3",
					Flags: net.FlagUp | net.FlagBroadcast,
				},
			},
			output: []string{
				"test0",
				"test3",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ifList := ifinfo.IfUpNameList(tt.input)
			assert.ElementsMatch(t, tt.output, ifList)
		})
	}
}
