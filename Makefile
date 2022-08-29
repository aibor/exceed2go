CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

export CGO_ENABLED := 0
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)

.PHONY: clean
clean:
	rm -rv internal/ttlToGo/bpf_bpfe*o

internal/ttlToGo/bpf_bpfel.go: bpf/ttltogo.c
	go generate ./internal/ttlToGo/loader.go

rootrd/init: internal/ttlToGo/loader_test.go internal/ttlToGo/bpf_bpfel.go
	go test -c -o $@ ./internal/ttlToGo/

rootrd.gz: rootrd/init
	pushd rootrd/ && find . | cpio -o -H newc | gzip -c > ../rootrd.gz && popd

.PHONY: testbpf
testbpf: rootrd.gz
	qemu-system-x86_64 -kernel /boot/vmlinuz-linux -initrd rootrd.gz \
		-serial stdio -display none \
		-append 'root=/dev/ram0 console=ttyAMA0 console=ttyS0 panic=-1 -- -test.v' < /dev/null
