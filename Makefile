SHELL := /bin/sh

CARGO ?= cargo
DOCKER ?= docker
PREFIX ?= $(HOME)/.local
DESTDIR ?=
CARGO_TARGET_DIR ?= $(CURDIR)/target
export CARGO_TARGET_DIR

DEBUG_DIR := $(CARGO_TARGET_DIR)/debug
RELEASE_DIR := $(CARGO_TARGET_DIR)/release
RELEASE_FAST_DIR := $(CARGO_TARGET_DIR)/release-fast

V ?= 0
VERBOSE_FLAG :=
ifneq ($(V),0)
    VERBOSE_FLAG := -v
endif

STATIC ?= 0
ifneq ($(STATIC),0)
    export RUSTFLAGS := $(RUSTFLAGS) -C target-feature=+crt-static
endif

CARGO_FLAGS ?=

.DEFAULT_GOAL := help
.NOTPARALLEL: check

.PHONY: help build build-fast release release-fast static release-static run doctor test lint fmt fmt-check examples check install

help:
	@printf '%s\n' \
		'Common development commands:' \
		'  make build          Build the CLI and every bundled plugin' \
		'  make build-fast     Build optimized binaries using fast release profile' \
		'  make release        Build fully optimized release binaries' \
		'  make static         Build static release binaries (crt-static)' \
		'  make run ARGS="..." Build, then run the development CLI' \
		'  make doctor         Build, then check local prerequisites' \
		'  make test           Test the complete workspace' \
		'  make lint           Run strict Clippy checks' \
		'  make fmt            Format all Rust code' \
		'  make fmt-check      Check formatting without changing files' \
		'  make examples       Validate both Compose examples' \
		'  make check          Run the full local verification gate' \
		'  make install        Install release binaries under PREFIX/bin' \
		'' \
		'Options:' \
		'  V=1                 Verbose build output (-v)' \
		'  STATIC=1            Enable static linking' \
		'  PREFIX=/path        Installation directory (default: ~/.local)'

build:
	$(CARGO) build $(VERBOSE_FLAG) $(CARGO_FLAGS) --workspace --locked

build-fast:
	$(CARGO) build $(VERBOSE_FLAG) $(CARGO_FLAGS) --workspace --locked --profile release-fast

release:
	$(CARGO) build $(VERBOSE_FLAG) $(CARGO_FLAGS) --release --workspace --locked

release-fast: build-fast

HOST_TARGET := $(shell rustc -vV 2>/dev/null | sed -n 's/host: //p')
TARGET ?= $(HOST_TARGET)
TARGET_ENV_VAR := CARGO_TARGET_$(shell echo $(TARGET) | tr '[:lower:]-' '[:upper:]_' | tr '.' '_')_RUSTFLAGS

static:
	$(TARGET_ENV_VAR)="$(RUSTFLAGS) -C target-feature=+crt-static" $(CARGO) build $(VERBOSE_FLAG) $(CARGO_FLAGS) --release --workspace --locked --target $(TARGET)

release-static: static

run: build
	$(DEBUG_DIR)/lightrail $(ARGS)

doctor: build
	$(DEBUG_DIR)/lightrail doctor

test:
	$(CARGO) test $(VERBOSE_FLAG) $(CARGO_FLAGS) --workspace --locked

lint:
	$(CARGO) clippy $(VERBOSE_FLAG) $(CARGO_FLAGS) --workspace --all-targets --all-features --locked -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

examples:
	$(DOCKER) compose -f examples/single-app/compose.yaml config --quiet
	$(DOCKER) compose -f examples/multi-app/compose.yaml config --quiet

check: fmt-check lint test examples
	git diff --check
	git diff --cached --check

install: release
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 \
		$(RELEASE_DIR)/lightrail \
		$(RELEASE_DIR)/lightrail-plugin-compose \
		$(RELEASE_DIR)/lightrail-plugin-fly \
		$(RELEASE_DIR)/lightrail-plugin-hetzner \
		$(RELEASE_DIR)/lightrail-plugin-kubernetes \
		$(RELEASE_DIR)/lightrail-plugin-ssh \
		"$(DESTDIR)$(PREFIX)/bin/"
