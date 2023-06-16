MAKEFLAGS := --no-builtin-rules
SHELL := bash
.ONESHELL:

BIN_DIR ?= bin
BINARY ?= $(BIN_DIR)/exceed2go
BPF_FILE := bpf/exceed2go.c
BPF2GO_FILE := internal/exceed2go/bpf_bpfel.go
BPF_TEST_FILE := internal/exceed2go/loader_test.go
INITRD_FILE ?= rootrd.gz
TEST_INIT_FILE ?= rootrd/init
KERNEL_FILE ?= /boot/vmlinuz-linux
LIBBPF ?= bpf/libbpf

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -Wshadow -I$(realpath $LIBBPF) $(CFLAGS) -nostdinc

export CGO_ENABLED := 0

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
		$(patsubst %.go,%.*,$(BPF2GO_FILE))

.PHONY: bpf
bpf: $(BPF2GO_FILE)

$(BPF2GO_FILE): $(BPF_FILE) $(LIBBPF)/*.h
	pushd $(@D)
	GOPACKAGE=exceed2go go run github.com/cilium/ebpf/cmd/bpf2go -cc $(CLANG) \
		-target bpfel \
		-cflags "$(CFLAGS)" \
		-no-strip \
		bpf $$(popd >/dev/null; realpath $(BPF_FILE))
	llvm-objdump \
		--source \
		--no-show-raw-insn \
		-g \
		$(patsubst %.go,%.o,$(@F)) \
		> $(patsubst %.go,%.dump,$(@F))

$(TEST_INIT_FILE): $(BPF_TEST_FILE) $(BPF2GO_FILE)
	go test -tags pidone -c -o $@ ./$(<D)

$(INITRD_FILE): $(TEST_INIT_FILE)
	pushd $(<D)
	find . | cpio -o -H newc | gzip -c > ../$@

.PHONY: testbpf
testbpf: $(INITRD_FILE)
	@qemu-system-x86_64 \
		-kernel $(KERNEL_FILE) \
		-initrd $< \
		-enable-kvm \
		-m 128 \
		-serial stdio \
		-display none \
		-append 'root=/dev/ram0 console=ttyAMA0 console=ttyS0 panic=-1 quiet -- -test.v' \
		< /dev/null
