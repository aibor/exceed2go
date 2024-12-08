# SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

MAKEFLAGS := --no-builtin-rules
.ONESHELL:

BIN_DIR ?= bin
BPF_PACKAGE_DIR := ./internal/bpf

BINARY ?= $(BIN_DIR)/exceed2go

PIDONETEST_KERNEL ?= test-kernel

GOBIN := $(shell realpath ./gobin)
VIRTRUN := $(GOBIN)/virtrun
BPF2GO := $(GOBIN)/bpf2go
STRINGER := $(GOBIN)/stringer

LIBBPF ?= bpf/libbpf
BPF_SRC_FILE := bpf/exceed2go.c
BPF2GO_FILE := $(BPF_PACKAGE_DIR)/exceed2go_bpfel.go

CC = clang
CFLAGS := -O2 -g -v \
		  -Wall -Werror -Wshadow \
		  -nostdinc -mcpu=v3 \
		  -I$(shell realpath $(LIBBPF)) \
		  $(CFLAGS)

export CGO_ENABLED := 0
export GOBIN

build: $(BINARY)
bpf: $(BPF2GO_FILE)

$(VIRTRUN): go.mod
	go install github.com/aibor/virtrun

$(BPF2GO): go.mod
	go install github.com/cilium/ebpf/cmd/bpf2go

$(STRINGER): go.mod
	go install golang.org/x/tools/cmd/stringer

$(BINARY): $(shell find . -name '*.go' ! -name '*_test.go') $(BPF2GO_FILE)
	go build -o "$@"

$(BPF2GO_FILE): $(BPF2GO) $(STRINGER) $(BPF_SRC_FILE) $(LIBBPF)/*.h Makefile
	cd $(@D)
	GOPACKAGE=bpf $(BPF2GO) \
		-cc $(CC) \
		-target bpfel \
		-cflags "$(CFLAGS)" \
		-no-strip \
		Exceed2Go $(shell realpath $(BPF_SRC_FILE))
	llvm-objdump \
		--source \
		--no-show-raw-insn \
		-g \
		$(patsubst %.go,%.o,$(@F)) \
		> $(patsubst %.go,%.dump,$(@F))
	$(STRINGER) \
		-type Exceed2GoCounterKey \
		-trimprefix Exceed2GoCounterKeyCOUNTER_ \
		-output exceed2go_counter_key_string.go \
		exceed2go_bpfel.go


.PHONY: pidonetest
pidonetest: $(BPF2GO_FILE) $(VIRTRUN)
	CGO_ENABLED=1 go test \
		-exec "$(VIRTRUN) \
			-kernel $$(realpath $(PIDONETEST_KERNEL))" \
		-v \
		-race \
		-coverpkg $$(go list ./... | tr '\n' ,) \
		-cover \
		-covermode atomic \
		-coverprofile /tmp/cover.out \
		$(PIDONETEST_FLAGS) \
		./...

.PHONY: clean
clean:
	@rm -frv \
		$(BINARY)

.PHONY: cleangen
cleangen:
	@rm -frv \
		$(BPF2GO_FILE) \
		$(patsubst %.go,%.dump,$(BPF2GO_FILE)) \
		$(patsubst %.go,%.o,$(BPF2GO_FILE)) \
		$(BPF_PACKAGE_DIR)/*_string.go
