// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"os"
)

const pinDirPerm os.FileMode = 0o755

type AttachOptions struct {
	IfaceIndex int
	Mode       Mode
	Layer      Layer
	HopList    HopList
}

// Attach attaches exceed2go to the interface specified in the [AttachOptions].
//
// It loads the eBPF objects, pins the maps to an interface specific BPFFS
// directory and attaches the program to the interface.
func Attach(opts AttachOptions) error {
	switch {
	case opts.IfaceIndex < 1:
		return ErrInvalidInterface
	case len(opts.HopList) < 1:
		return ErrEmptyHopList
	}

	pinDir := ifaceDir(opts.IfaceIndex)

	var err error
	defer func() {
		if err != nil {
			RemoveIface(opts.IfaceIndex)
		}
	}()

	err = os.MkdirAll(pinDir, pinDirPerm)
	if err != nil {
		return fmt.Errorf("create bpf pin dir: %v", err)
	}

	objs, err := load(pinDir)
	if err != nil {
		return err
	}
	defer objs.Close() //nolint:errcheck

	prog, err := program(objs, opts.Mode, opts.Layer)
	if err != nil {
		return err
	}

	err = writeAddrs(objs.Exceed2goAddrs, opts.HopList)
	if err != nil {
		return err
	}

	lnk, err := prog.attach(opts.IfaceIndex)
	if err != nil {
		return err
	}
	defer lnk.Close() //nolint:errcheck

	err = lnk.Pin(ifacePath(opts.IfaceIndex, "link"))
	if err != nil {
		return err
	}

	return nil
}
