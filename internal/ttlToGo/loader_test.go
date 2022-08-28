package ttlToGo

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func sysfs(m *testing.M) error {
	if (os.Getpid() != 1) {
		return nil
	}

	if err := syscall.Mkdir("/sys", 0755); err != nil {
		return fmt.Errorf("mkdir /sys: %v", err)
	}

	if err := syscall.Mount("sysfs", "/sys", "sysfs", uintptr(syscall.MS_NOEXEC), ""); err != nil {
		return fmt.Errorf("mount /sys: %v", err)
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
	defer poweroff()

	if err := sysfs(m); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Run tests")
	return m.Run()
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
		HopLimit: uint8(62),
	}

	icmp6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, 0),
	}

	payload := gopacket.Payload([]byte{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4})
	icmp6.SetNetworkLayerForChecksum(&ipv6)

	gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmp6, &payload)

	return buf.Bytes()
}

func load(tb testing.TB) *bpfObjects {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		tb.Errorf("error loading objects: %v", err)
	}
	return &objs
}

func TestLoad(t *testing.T) {
	objs := load(t)
	defer objs.Close()
}

func TestTTL(t *testing.T) {
	objs := load(t)
	defer objs.Close()

	pkt := packet()
	t.Logf("in length: %d", len(pkt))
	t.Log(hex.EncodeToString(pkt))
	ret, out, err := objs.XdpTtltogo.Test(pkt)
	if err != nil {
		t.Errorf("test error: %v", err)
		t.Fail()
		return
	}

	t.Logf("out length: %d", len(out))
	t.Log(hex.EncodeToString(out))

	if ret != 2 {
		t.Errorf("wrong return value: %d", ret)
		t.Fail()
		return
	}
}
