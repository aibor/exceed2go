// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Mode int

const (
	ModeXDP Mode = iota
	ModeTC
)

type Layer int

const (
	Layer2 Layer = iota
	Layer3
)

type attacher interface {
	attach(ifaceIndex int) (link.Link, error)
}

func program( //nolint:ireturn
	objs *bpf.Exceed2GoObjects,
	mode Mode,
	layer Layer,
) (attacher, error) {
	switch mode {
	case ModeXDP:
		return newXdp(objs, layer)
	case ModeTC:
		return newTc(objs, layer)
	default:
		return nil, ErrUnknownMode
	}
}

type xdp struct {
	*ebpf.Program
}

func newXdp(objs *bpf.Exceed2GoObjects, layer Layer) (*xdp, error) {
	switch layer {
	case Layer2:
		return &xdp{objs.Exceed2goXdpL2}, nil
	case Layer3:
		return nil, ErrXDPLayer3NotSupported
	default:
		return nil, ErrUnknownLayer
	}
}

func (p *xdp) attach(ifaceIndex int) (link.Link, error) { //nolint:ireturn
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   p.Program,
		Interface: ifaceIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}

	return lnk, nil
}

type tc struct {
	*ebpf.Program
}

func newTc(objs *bpf.Exceed2GoObjects, layer Layer) (*tc, error) {
	switch layer {
	case Layer2:
		return &tc{objs.Exceed2goTcL2}, nil
	case Layer3:
		return &tc{objs.Exceed2goTcL3}, nil
	default:
		return nil, ErrUnknownLayer
	}
}

func (p *tc) attach(ifaceIndex int) (link.Link, error) { //nolint:ireturn
	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   p.Program,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifaceIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}

	return lnk, nil
}
