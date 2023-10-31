MAKEFLAGS := --no-builtin-rules
SHELL := bash
.ONESHELL:

BIN_DIR ?= bin
BPF_PACKAGE_DIR := ./internal/bpf

BINARY ?= $(BIN_DIR)/exceed2go

KERNEL_FILE ?= /boot/vmlinuz-linux

GOBIN := $(shell realpath ./gobin)
PIDONETEST := $(GOBIN)/pidonetest
BPF2GO := $(GOBIN)/bpf2go
STRINGER := $(GOBIN)/stringer

LIBBPF ?= bpf/libbpf
BPF_SRC_FILE := bpf/exceed2go.c
BPF2GO_FILE := $(BPF_PACKAGE_DIR)/exceed2go_bpfel.go

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -Wshadow -I$(realpath $LIBBPF) $(CFLAGS) -nostdinc

PIDONETEST_KERNEL ?= /boot/vmlinuz-linux
PIDONETEST_ARGS ?= 

export CGO_ENABLED := 0
export GOBIN

build: $(BINARY)
bpf: $(BPF2GO_FILE)

$(PIDONETEST):
	go install github.com/aibor/pidonetest/cmd/pidonetest

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
pidonetest: $(BPF2GO_FILE) $(PIDONETEST)
	go test \
		-exec "$(PIDONETEST) \
			-kernel $(PIDONETEST_KERNEL) \
			$(PIDONETEST_ARGS)" \
		-v \
		-cover \
		-covermode atomic \
		./...

.PHONY: pidonetest-arm64
pidonetest-arm64: $(BPF2GO_FILE) $(PIDONETEST)
	GOARCH=arm64 go test \
		-tags pidonetest \
		-exec "$(PIDONETEST) \
		    -nokvm \
		    -standalone \
			-kernel $(PIDONETEST_KERNEL) \
			-qemu-bin qemu-system-aarch64 \
			-machine virt \
			-cpu max
			$(PIDONETEST_ARGS)" \
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
