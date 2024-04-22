// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"errors"
)

var (
	// Returned if the interface index is invalid.
	ErrInvalidInterface = errors.New("invalid Interface")
	// Returned if an empty [HopList] is passed.
	ErrEmptyHopList = errors.New("hop list is empty")
	// Returned if the given [Mode] is not defined.
	ErrUnknownMode = errors.New("unknown mode")
	// Returned if the given [Layer] is not defined.
	ErrUnknownLayer = errors.New("unknown layer")
)
