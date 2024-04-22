// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bpf

type SkBuff struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	Cb             [5]uint32
	Hash           uint32
	TcClassid      uint32
	Data           uint32
	DataEnd        uint32
	NapiID         uint32
	Family         uint32
	RemoteIP4      [4]uint8
	LocalIP4       [4]uint8
	RemoteIP6      [16]uint8
	LocalIP6       [16]uint8
	RemotePort     uint32
	LocalPort      uint32
	DataMeta       uint32
	FlowKeys       uint64
	Tstamp         uint64
	WireLen        uint32
	GsoSegs        uint32
	Sk             uint64
	GsoSize        uint32
	TstampType     uint8
	_              [3]byte
	Hwtstamp       uint64
}

type XdpMd struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}
