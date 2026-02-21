// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

module github.com/aibor/exceed2go

go 1.25.3

require (
	github.com/cilium/ebpf v0.20.0
	github.com/gopacket/gopacket v1.5.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/aibor/cpio v0.1.0 // indirect
	github.com/aibor/virtrun v0.15.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/aibor/virtrun
	github.com/cilium/ebpf/cmd/bpf2go
	golang.org/x/tools/cmd/stringer
)
