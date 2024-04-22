// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
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
		t.Run(tt.name, func(t *testing.T) {
			ifList := ifaceUpNameList(tt.input)
			assert.ElementsMatch(t, tt.output, ifList)
		})
	}
}
