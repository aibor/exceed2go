package exceed2go_test

import (
	"fmt"
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
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameTCL2Prog))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameTCL3Prog))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameXDPL2Prog))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameXDPL3Prog))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameConfigMap))
	assert.FileExists(t, exceed2go.BPFFSPath(exceed2go.PinFileNameStatsMap))
	assert.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin again")
}

func TestAttachProg(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	require.NoError(t, err, "get test interface")

	tests := []struct {
		name         string
		prog         exceed2go.PinFileName
		infoTestFunc func(*testing.T, *link.Info)
	}{
		{
			name: "xdp_l2",
			prog: exceed2go.PinFileNameXDPL2Prog,
			infoTestFunc: func(t *testing.T, i *link.Info) {
				xdp := i.XDP()
				require.NotNil(t, xdp, "link.Info.XDP")
				assert.Equal(t, iface.Index, int(xdp.Ifindex), "link interface index matches test interface")
			},
		},
		{
			name: "xdp_l3",
			prog: exceed2go.PinFileNameXDPL3Prog,
			infoTestFunc: func(t *testing.T, i *link.Info) {
				xdp := i.XDP()
				require.NotNil(t, xdp, "link.Info.XDP")
				assert.Equal(t, iface.Index, int(xdp.Ifindex), "link interface index matches test interface")
			},
		},
		{
			name: "tc_l2",
			prog: exceed2go.PinFileNameTCL2Prog,
			infoTestFunc: func(t *testing.T, i *link.Info) {
				tcx := i.TCX()
				require.NotNil(t, tcx, "link.Info.TC")
				assert.Equal(t, iface.Index, int(tcx.Ifindex), "link interface index matches test interface")
			},
		},
		{
			name: "tc_l3",
			prog: exceed2go.PinFileNameTCL3Prog,
			infoTestFunc: func(t *testing.T, i *link.Info) {
				tcx := i.TCX()
				require.NotNil(t, tcx, "link.Info.TC")
				assert.Equal(t, iface.Index, int(tcx.Ifindex), "link interface index matches test interface")
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(exceed2go.Remove)
			require.NoError(t, exceed2go.LoadAndPin(), "LoadAndPin")

			require.NotEmpty(t, iface.Index, "must be valid test interface index")
			require.NoError(t, exceed2go.AttachProg(tt.prog, iface), "attach must succeed")

			linkName := exceed2go.PinFileName(
				fmt.Sprintf("%s-%d", exceed2go.PinFileNameLink, iface.Index),
			)
			require.FileExists(t, exceed2go.BPFFSPath(linkName))

			lnk, err := link.LoadPinnedLink(exceed2go.BPFFSPath(linkName), nil)
			require.NoError(t, err, "LoadPinnedLink")

			info, err := lnk.Info()
			require.NoError(t, err, "link.Info")

			tt.infoTestFunc(t, info)
		})
	}
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

	_, err := exceed2go.GetStats()
	assert.NoError(t, err, "GetStats")
}
