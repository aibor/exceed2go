MAKEFLAGS := --no-builtin-rules
SHELL := bash
.ONESHELL:

BIN_DIR ?= bin
BPF_PACKAGE_DIR := ./internal/bpf

BINARY ?= $(BIN_DIR)/exceed2go

KERNEL_FILE ?= /boot/vmlinuz-linux

GOBIN := $(shell realpath ./gobin)
VIRTRUN := $(GOBIN)/virtrun
BPF2GO := $(GOBIN)/bpf2go
STRINGER := $(GOBIN)/stringer

LIBBPF ?= bpf/libbpf
BPF_SRC_FILE := bpf/exceed2go.c
BPF2GO_FILE := $(BPF_PACKAGE_DIR)/exceed2go_bpfel.go

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -Wshadow -I$(realpath $LIBBPF) $(CFLAGS) -nostdinc -v

export CGO_ENABLED := 0
export GOBIN

build: $(BINARY)
bpf: $(BPF2GO_FILE)

$(VIRTRUN):
	go install github.com/aibor/virtrun

$(BPF2GO):
	go install github.com/cilium/ebpf/cmd/bpf2go

$(STRINGER):
	go install golang.org/x/tools/cmd/stringer

$(BINARY): $(shell find . -name '*.go' ! -name '*_test.go') $(BPF2GO_FILE)
	go build -o "$@"

$(BPF2GO_FILE): $(BPF2GO) $(STRINGER) $(BPF_SRC_FILE) $(LIBBPF)/*.h
	pushd $(@D)
	GOPACKAGE=bpf $(BPF2GO) \
		-cc $(CLANG) \
		-target bpfel \
		-cflags "$(CFLAGS)" \
		-no-strip \
		Exceed2Go $$(popd >/dev/null; realpath $(BPF_SRC_FILE))
	llvm-objdump \
		--source \
		--no-show-raw-insn \
		-g \
		$(patsubst %.go,%.o,$(@F)) \
		> $(patsubst %.go,%.dump,$(@F))
	$(STRINGER) \
		-type Exceed2GoCounterKey \
		-trimprefix Exceed2GoCounterKey \
		exceed2go_bpfel.go

.PHONY: pidonetest
pidonetest: $(BPF2GO_FILE) $(VIRTRUN)
	go test \
		-exec "$(VIRTRUN) \
			-kernel $(PIDONETEST_KERNEL)" \
		-v \
		-cover \
		-covermode atomic \
		./...

.PHONY: clean
clean:
	@rm -frv \
		$(BINARY)

.PHONY: cleangen
cleangen:
	@rm -frv \
		$(patsubst %.go,%.*,$(BPF2GO_FILE)) \
		$(BPF_PACKAGE_DIR)/*_string.go
