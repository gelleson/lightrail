SHELL := /bin/sh

CARGO ?= cargo
DOCKER ?= docker
PREFIX ?= $(HOME)/.local
DESTDIR ?=
CARGO_TARGET_DIR ?= $(CURDIR)/target
export CARGO_TARGET_DIR

DEBUG_DIR := $(CARGO_TARGET_DIR)/debug
RELEASE_DIR := $(CARGO_TARGET_DIR)/release

.DEFAULT_GOAL := help
.NOTPARALLEL: check

.PHONY: help build release run doctor test lint fmt fmt-check examples check install

help:
	@printf '%s\n' \
		'Common development commands:' \
		'  make build          Build the CLI and every bundled plugin' \
		'  make run ARGS="..." Build, then run the development CLI' \
		'  make doctor         Build, then check local prerequisites' \
		'  make test           Test the complete workspace' \
		'  make lint           Run strict Clippy checks' \
		'  make fmt            Format all Rust code' \
		'  make fmt-check      Check formatting without changing files' \
		'  make examples       Validate both Compose examples' \
		'  make check          Run the full local verification gate' \
		'  make release        Build optimized binaries' \
		'  make install        Install release binaries under PREFIX/bin'

build:
	$(CARGO) build --workspace --locked

release:
	$(CARGO) build --release --workspace --locked

run: build
	$(DEBUG_DIR)/lightrail $(ARGS)

doctor: build
	$(DEBUG_DIR)/lightrail doctor

test:
	$(CARGO) test --workspace --locked

lint:
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

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
