// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"errors"

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

func program(objs *bpf.Exceed2GoObjects, mode Mode, layer Layer) (attacher, error) {
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

func newXdp(objs *bpf.Exceed2GoObjects, layer Layer) (attacher, error) {
	switch layer {
	case Layer2:
		return xdp{objs.Exceed2goXdpL2}, nil
	case Layer3:
		return nil, errors.New("layer 3 interfaces do not support XDP, try TC)")
	default:
		return nil, ErrUnknownLayer
	}
}

func (p xdp) attach(ifaceIndex int) (link.Link, error) {
	return link.AttachXDP(link.XDPOptions{
		Program:   p.Program,
		Interface: ifaceIndex,
	})
}

type tc struct {
	*ebpf.Program
}

func newTc(objs *bpf.Exceed2GoObjects, layer Layer) (attacher, error) {
	switch layer {
	case Layer2:
		return tc{objs.Exceed2goTcL2}, nil
	case Layer3:
		return tc{objs.Exceed2goTcL3}, nil
	default:
		return nil, ErrUnknownLayer
	}
}

func (p tc) attach(ifaceIndex int) (link.Link, error) {
	return link.AttachTCX(link.TCXOptions{
		Program:   p.Program,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifaceIndex,
	})
}
