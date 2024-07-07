// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"errors"
)

var (
	// ErrInvalidInterface is returned if the interface index is invalid.
	ErrInvalidInterface = errors.New("invalid Interface")
	// ErrEmptyHopList is returned if an empty [HopList] is passed.
	ErrEmptyHopList = errors.New("hop list is empty")
	// ErrUnknownMode is returned if the given [Mode] is not defined.
	ErrUnknownMode = errors.New("unknown mode")
	// ErrUnknownLayer is returned if the given [Layer] is not defined.
	ErrUnknownLayer = errors.New("unknown layer")
)
