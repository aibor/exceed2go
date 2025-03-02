// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bpf

//go:generate go tool bpf2go -target bpfel -cflags "-v -Wall -Werror -Wshadow -nostdinc" -no-strip Exceed2Go ../../bpf/exceed2go.c
//go:generate go tool stringer -type Exceed2GoCounterKey -trimprefix Exceed2GoCounterKeyCOUNTER_ -output exceed2go_counter_key_string.go
