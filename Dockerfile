# SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# syntax=docker/dockerfile:1

ARG KERNEL_VERSION=6.6

FROM alpine:3.21 AS go-image

RUN --mount=type=cache,target=/var/cache/apk \
  apk add \
    go \
    make

# Build:
#   podman build --rm --tag exceed2go-build --target build-image .
#
# Run:
#  podman run --rm \
#    --volume $PWD:/data \
#    exceed2go-build:latest
#
FROM go-image AS build-image

WORKDIR /tmp/download
ADD go.mod go.sum ./
RUN go mod download -x

VOLUME /data
WORKDIR /data

CMD make build

# Build:
#   podman build --rm --tag exceed2go-build-bpf --target build-bpf-image .
#
# Run:
#  podman run --rm \
#    --volume $PWD:/data \
#    exceed2go-build-bpf:latest
#
FROM build-image AS build-bpf-image

ARG LLVM_VERSION=17
RUN --mount=type=cache,target=/var/cache/apk \
  apk add \
    "clang${LLVM_VERSION}" \
    "llvm${LLVM_VERSION}"

CMD make bpf

# Build:
#   podman build --rm --tag exceed2go-test --target test-image .
#
# Run:
#   podman run --rm \
#     --volume $PWD:/data \
#     --device /dev/kvm \
#     exceed2go-test:latest
#
# Run with different kernel:
#   podman run --rm \
#     --volume $PWD:/data \
#     --mount type=image,source=ghcr.io/cilium/ci-kernels:6.7,destination=/k \
#     --device /dev/kvm \
#     --env KERNEL=/k/boot/vmlinuz \
#     exceed2go-test:latest
#
FROM ghcr.io/cilium/ci-kernels:${KERNEL_VERSION} AS test-kernel
FROM build-image AS test-image

RUN --mount=type=cache,target=/var/cache/apk \
  apk add \
    qemu-system-x86_64

COPY --from=test-kernel /boot/vmlinuz /vmlinuz
 
ENV KERNEL=/vmlinuz
CMD make pidonetest PIDONETEST_KERNEL=${KERNEL}

FROM build-image

