package ttlToGo

import (
	"fmt"
	"net"

	_ "github.com/cilium/ebpf"
	//"github.com/vishvananda/netlink"
)

type MapIP struct {
	hopLimit int
	addr string
}

func Load() (*bpfObjects, error) {
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &objs, nil
}

func (o *bpfObjects) SetAddr(idx int, addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("Cannot parse IP: %s", addr)
	}

	if err := o.TtlAddrs.Put(uint32(idx), []byte(ip)); err != nil {
		return fmt.Errorf("map load error: %w", err)
	}

	return nil
}

func (o *bpfObjects) GetStats() []uint32 {
	var (
		nextKey uint32
		lookupKeys   = make([]uint32, 8)
		lookupValues = make([]uint32, 8)
	)

	o.TtlCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	return lookupValues
}
