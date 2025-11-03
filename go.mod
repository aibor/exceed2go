// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

module github.com/aibor/exceed2go

go 1.25.3

require (
	github.com/cilium/ebpf v0.20.0
	github.com/gopacket/gopacket v1.4.0
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/aibor/virtrun v0.13.1 // indirect
	github.com/cavaliergopher/cpio v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/aibor/virtrun
	github.com/cilium/ebpf/cmd/bpf2go
	golang.org/x/tools/cmd/stringer
)
