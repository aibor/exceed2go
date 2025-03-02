# SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

MAKEFLAGS := --no-builtin-rules
.ONESHELL:

BIN_DIR ?= bin
BPF_PACKAGE_DIR := ./internal/bpf

BINARY ?= $(BIN_DIR)/exceed2go

PIDONETEST_KERNEL ?= test-kernel

BPF2GO_FILE := $(BPF_PACKAGE_DIR)/exceed2go_bpfel.go


build: $(BINARY)

bpf: $(BPF2GO_FILE)

$(BINARY): $(shell find . -name '*.go' ! -name '*_test.go') $(BPF2GO_FILE)
	CGO_ENABLED=0 go build -o "$@"

$(BPF2GO_FILE): $(wildcard bpf/*) $(wildcard bpf/libbpf/*) Makefile
	go generate ./internal/bpf
	llvm-objdump \
		--source \
		--no-show-raw-insn \
		-g \
		$(patsubst %.go,%.o,$@) \
		> $(patsubst %.go,%.dump,$@)

.PHONY: pidonetest
pidonetest: $(BPF2GO_FILE)
	CGO_ENABLED=1 go test \
		-exec "go tool virtrun \
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
