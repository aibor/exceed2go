package ttlToGo

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func mountfs(m *testing.M, path, fstype string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %v", path, err)
	}

	if err := syscall.Mount("", path, fstype, uintptr(syscall.MS_NOEXEC), ""); err != nil {
		return fmt.Errorf("mount %s: %v", path, err)
	}

	return nil
}

func poweroff() {
	if (os.Getpid() != 1) {
		return
	}

	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

func run(m *testing.M) int {
	fmt.Println("Init")

	startprint := make(chan struct{})

	if (os.Getpid() == 1) {
		defer poweroff()

		mounts := map[string]string{
			"/sys": "sysfs",
			"/sys/kernel/debug": "debugfs",
			"/sys/kernel/debug/tracing": "tracefs",
			"/proc": "proc",
		}

		for mp, t := range mounts {
			if err := mountfs(m, mp, t); err != nil {
				fmt.Println(err)
				return 1
			}
		}

		time.Sleep(100 * time.Millisecond)
		go func() {
			f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
			if err != nil {
				fmt.Printf("error opening trace pipe: %v\n", err)
				return
			}
			r := bufio.NewReader(f)
			<-startprint
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					fmt.Println("err")
					continue
				}
				fmt.Printf(l)
			}
		}()


		if err := os.WriteFile("/proc/sys/kernel/printk", []byte("0"), 0755); err != nil {
			fmt.Printf("setting printk: %v\n", err)
			return 1
		}
	}

	fmt.Println("Run tests")
	ret := m.Run()
	fmt.Println("Print trace")
	close(startprint)
	time.Sleep(500 * time.Millisecond)
	return ret
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func packet() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := layers.IPv6{
		Version: uint8(6),
		SrcIP: net.ParseIP("fd01::4"),
		DstIP: net.ParseIP("fd01::ff"),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit: uint8(1),
	}

	icmp6 := layers.ICMPv6 {
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmp6echo := layers.ICMPv6Echo {
		Identifier: 1,
		SeqNumber: 1,
	}

	payload := gopacket.Payload([]byte{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4})
	icmp6.SetNetworkLayerForChecksum(&ipv6)

	gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmp6, &icmp6echo, &payload)

	return buf.Bytes()
}

func load(tb testing.TB) *bpfObjects {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		tb.Errorf("error loading objects: %v", err)
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			tb.Logf("verifier log:\n %s", strings.Join(ve.Log, "\n"))
		}

		tb.Fail()
		return nil
	}
	return &objs
}

func TestLoad(t *testing.T) {
	objs := load(t)
	if objs == nil {
		return
	}
	defer objs.Close()
}

func TestTTL(t *testing.T) {
	objs := load(t)
	if objs == nil {
		return
	}
	defer objs.Close()

	if err := objs.TtlAddrs.Put(uint32(0), []byte(net.ParseIP("fd01::ff"))); err != nil {
		t.Errorf("map load error: %v", err)
		t.Fail()
		return
	}

	if err := objs.TtlAddrs.Put(uint32(1), []byte(net.ParseIP("fd01::ee"))); err != nil {
		t.Errorf("map load error: %v", err)
		t.Fail()
		return
	}

	pkt := packet()
	t.Logf("in length: %d", len(pkt))
	t.Log(hex.EncodeToString(pkt))
	ret, out, err := objs.XdpTtltogo.Test(pkt)
	if err != nil {
		t.Errorf("test error: %v", err)
		t.Fail()
		return
	}

	var nextKey uint32
	var lookupKeys   = make([]uint32, 8)
	var lookupValues = make([]uint32, 8)
	objs.TtlCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	for idx, key := range lookupKeys {
		t.Logf("%d: %d", key, lookupValues[idx])
		if key == nextKey {
			break
		}
	}

	t.Logf("out length: %d", len(out))
	t.Log(hex.EncodeToString(out))

	if ret != 3 {
		t.Errorf("wrong return value: %d", ret)
		t.Fail()
		return
	}
}
