MAKEFLAGS := --no-builtin-rules
SHELL := bash
.ONESHELL:

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

export CGO_ENABLED := 0

BIN_DIR ?= bin
BINARY ?= $(BIN_DIR)/exceed2go
BPF_FILE := bpf/exceed2go.c
BPF2GO_FILE := internal/exceed2go/bpf_bpfel.go
BPF_TEST_FILE := internal/exceed2go/loader_test.go
INITRD_FILE ?= rootrd.gz
TEST_INIT_FILE ?= rootrd/init
KERNEL_FILE ?= /boot/vmlinuz-linux

.PHONY: build
build: $(BINARY)

$(BINARY): $(shell find . -name '*.go' ! -name '*_test.go') $(BPF2GO_FILE)
	go build -o "$@"

.PHONY: clean
clean:
	@rm -frv \
		$(BINARY) \
		$(INITRD_FILE) \
		$(TEST_INIT_FILE)

.PHONY: cleangen
cleangen:
	@rm -frv \
		$(BPF2GO_FILE)
		$(patsubst %.go,%.o,$(BPF2GO_FILE))

$(BPF2GO_FILE): $(BPF_FILE) bpf/*.h
	pushd $(@D)
	GOPACKAGE=exceed2go go run github.com/cilium/ebpf/cmd/bpf2go -cc $(CLANG) \
		-target bpfel \
		-cflags "$(CFLAGS)" \
		bpf $$(popd >/dev/null; realpath $(BPF_FILE))

$(TEST_INIT_FILE): $(BPF_TEST_FILE) $(BPF2GO_FILE)
	go test -c -o $@ ./$(<D)

$(INITRD_FILE): $(TEST_INIT_FILE)
	pushd $(<D)
	find . | cpio -o -H newc | gzip -c > ../$@

.PHONY: testbpf
testbpf: $(INITRD_FILE)
	@qemu-system-x86_64 \
		-kernel $(KERNEL_FILE) \
		-initrd $< \
		-m 256 \
		-serial stdio \
		-display none \
		-append 'root=/dev/ram0 console=ttyAMA0 console=ttyS0 panic=-1 -- -test.v' \
		< /dev/null
