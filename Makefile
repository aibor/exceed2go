SHELL := bash
.ONESHELL:

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

export CGO_ENABLED := 0

BPF_FILE := bpf/ttltogo.c
BPF2GO_FILE := internal/ttlToGo/bpf_bpfel.go
BPF_TEST_FILE := internal/ttlToGo/loader_test.go
INITRD_FILE := rootrd.gz
TEST_INIT_FILE := rootrd/init
KERNEL_FILE := /boot/vmlinuz-linux

.PHONY: clean
clean:
	@rm -frv \
		$(BPF2GO_FILE) \
		$(patsubst %.go,%.o,$(BPF2GO_FILE)) \
		$(INITRD_FILE) \
		$(TEST_INIT_FILE)

$(BPF2GO_FILE): $(BPF_FILE) bpf/*.h
	pushd $(@D)
	GOPACKAGE=ttlToGo go run github.com/cilium/ebpf/cmd/bpf2go -cc $(CLANG) \
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
