// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package exceed2go

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfIn6Addr struct{ In6U struct{ U6Addr8 [16]uint8 } }

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	Exceed2goEcho     *ebpf.ProgramSpec `ebpf:"exceed2go_echo"`
	Exceed2goExceeded *ebpf.ProgramSpec `ebpf:"exceed2go_exceeded"`
	Exceed2goRoot     *ebpf.ProgramSpec `ebpf:"exceed2go_root"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Exceed2goAddrs    *ebpf.MapSpec `ebpf:"exceed2go_addrs"`
	Exceed2goCounters *ebpf.MapSpec `ebpf:"exceed2go_counters"`
	Exceed2goJumps    *ebpf.MapSpec `ebpf:"exceed2go_jumps"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Exceed2goAddrs    *ebpf.Map `ebpf:"exceed2go_addrs"`
	Exceed2goCounters *ebpf.Map `ebpf:"exceed2go_counters"`
	Exceed2goJumps    *ebpf.Map `ebpf:"exceed2go_jumps"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Exceed2goAddrs,
		m.Exceed2goCounters,
		m.Exceed2goJumps,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	Exceed2goEcho     *ebpf.Program `ebpf:"exceed2go_echo"`
	Exceed2goExceeded *ebpf.Program `ebpf:"exceed2go_exceeded"`
	Exceed2goRoot     *ebpf.Program `ebpf:"exceed2go_root"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.Exceed2goEcho,
		p.Exceed2goExceeded,
		p.Exceed2goRoot,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
