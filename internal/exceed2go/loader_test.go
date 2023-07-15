package exceed2go_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aibor/exceed2go/internal/exceed2go"
)

func TestLoadAndPin(t *testing.T) {
	t.Cleanup(exceed2go.Remove)
	require.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin")
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameXDPProg))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameConfigMap))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameStatsMap))
	assert.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin again")
}

func TestAttachProg(t *testing.T) {
	t.Cleanup(exceed2go.Remove)
	require.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin")

	iface, err := net.InterfaceByName("lo")
	require.NotEmpty(t, iface.Index, "must be valid test interface index")
	require.NoError(t, err, "get test interface")
	require.NoError(t, exceed2go.AttachProg(iface), "AttachProg")
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameXDPLink))

	lnk, err := link.LoadPinnedLink(exceed2go.BPFFSPath(exceed2go.PinFileNameXDPLink), nil)
	require.NoError(t, err, "LoadPinnedLink")

	info, err := lnk.Info()
	require.NoError(t, err, "link.Info")

	xdp := info.XDP()
	require.NotNil(t, xdp, "link.Info.XDP")

	assert.Equal(t, iface.Index, int(xdp.Ifindex), "link interface index matches test interface")
}

func TestSetAddrs(t *testing.T) {
	t.Cleanup(exceed2go.Remove)
	require.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin")

	hops := exceed2go.HopList{
		netip.MustParseAddr("fd01::1"),
		netip.MustParseAddr("fd01::2"),
		netip.MustParseAddr("fd01::3"),
	}

	assert.NoError(t, exceed2go.SetAddrs(hops), "SetAddrs")

	mapHops, err := exceed2go.GetAddrs()
	require.NoError(t, err, "GetAddrs()")
	assert.ElementsMatch(t, hops, mapHops, "hopLists should be equal")
}

func TestGetStats(t *testing.T) {
	t.Cleanup(exceed2go.Remove)
	require.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin")

	stats, err := exceed2go.GetStats()
	if assert.NoError(t, err, "GetStats") {
		t.Log(stats)
	}
}
