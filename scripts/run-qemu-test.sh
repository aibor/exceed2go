#!/bin/bash

set -eEuo pipefail

: ${KERNEL_FILE:=/boot/vmlinuz-linux}

# Change into the tmp dir where go built the test binary. Go test is cleaning
# up the temp dir, so we do not need to clean up.
pushd $(dirname $(realpath $1)) >/dev/null
mkdir rootrd
mv "$1" rootrd/init
shift
args="$*"

pushd rootrd >/dev/null
find . | cpio -o -H newc | gzip -c >../rootrd.gz
popd >/dev/null

rc=0
while read -r; do
	if [[ $REPLY =~ ^FAIL || $REPLY =~ "--- FAIL:" ]]; then
		rc=1
	fi
	echo "$REPLY"
done < <(qemu-system-x86_64 \
	-kernel "$KERNEL_FILE" \
	-initrd rootrd.gz \
	-enable-kvm \
	-m 128 \
	-serial stdio \
	-display none \
	-append "root=/dev/ram0 console=ttyAMA0 console=ttyS0 panic=-1 quiet -- $args" \
	</dev/null)

exit "$rc"
