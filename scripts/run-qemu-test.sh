#!/bin/bash

set -eEuo pipefail

: ${RUN_QEMU_TEST_DEBUG:=}
: ${RUN_QEMU_TEST_KERNEL:=/boot/vmlinuz-linux}
: ${RUN_QEMU_TEST_MEMORY:=128}

run_qemu() {
	local testargs=("$@")
	local sysargs=(
		root=/dev/ram0
		console=ttyAMA0
		console=ttyS0
		panic=-1
		quiet
	)
	local cmdline="${sysargs[*]} -- ${testargs[*]}"

	qemu-system-x86_64 \
		-kernel "$RUN_QEMU_TEST_KERNEL" \
		-initrd initrd \
		-enable-kvm \
		-m ${RUN_QEMU_TEST_MEMORY} \
		-no-reboot \
		-serial stdio \
		-display none \
		-append "$cmdline" \
		</dev/null
}

if [[ -n $RUN_QEMU_TEST_DEBUG ]]; then
	set -x
fi

testbinary="$1"
shift
args=("$@")

# Change into the tmp dir where go built the test binary. Go test is cleaning
# up the temp dir, so we do not need to clean up.
pushd "$(dirname "$(realpath "$testbinary")")" >/dev/null
# The test binary is the only thing executed in the test system so rename it
# to "init" which is the magic name the kernel is executing.
mv "$testbinary" init

# Build initrd cpio archive in SRV4 format.
echo init | cpio -o -H newc >initrd

rc=1
while read -r; do
	# Only our magic line is able to set rc to 0.
	if [[ $REPLY =~ ^PIDONE_GO_TEST_RC:\ ([0-9]+) ]]; then
		rc=${BASH_REMATCH[1]}
	else
		echo "$REPLY"
	fi
done < <(run_qemu "${args[@]}")

exit "$rc"
