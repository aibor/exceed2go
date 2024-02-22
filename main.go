// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"github.com/aibor/exceed2go/cmd"
	"os"
)

func main() {
	c := cmd.RootCmd()
	if err := c.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error: %v\n", os.Args[0], err)
		os.Exit(1)
	}
}
