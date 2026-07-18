# Contributing to Lightrail

Lightrail keeps its local workflow deliberately small: Rust with Rustfmt and
Clippy, Docker, Git, GNU Make, and OpenSSH are enough to build and verify the
whole repository.

## Start here

Install Rust 1.85 or newer, Git, Docker with Compose and Buildx, and an
OpenSSH-compatible client. Then run:

```console
make build
make doctor
make check
```

`make help` lists the common contributor commands. `make run` always
builds the CLI and its sibling plugins first, so this runs the development
binary with the complete plugin set:

```console
make run ARGS="--help"
make run ARGS="doctor"
```

To install optimized binaries together under `~/.local/bin`, run
`make install`. Override the destination with `PREFIX`, for example
`make install PREFIX=/usr/local`.

## Repository layout

- `crates/lightrail-core` contains provider-independent configuration,
  identity, Git, and hostname rules.
- `crates/lightrail-plugin-protocol` contains the versioned JSON-RPC contract.
- `crates/lightrail` contains CLI parsing, initialization, orchestration,
  output, secrets, and plugin discovery.
- `plugins/lightrail-plugin-compose` owns local builds, image transfer,
  Compose, Traefik, routing, and readiness.
- `plugins/lightrail-plugin-ssh` owns generic host bootstrap and remote locks.
- `plugins/lightrail-plugin-hetzner` owns Hetzner resources and machine locks.
- `examples` contains standalone projects for manual and smoke testing.
- `docs` contains the durable product, architecture, and protocol contracts.

Read `docs/product-spec.md` before changing behavior, `docs/architecture.md`
before moving responsibilities, and `docs/plugin-protocol.md` before changing
plugin messages. Coding agents should also read `AGENTS.md`.

## Focused checks

Use a package check or test during the inner loop:

```console
cargo check -p lightrail --locked
cargo test -p lightrail-plugin-compose --locked
```

Before handing off any change, run `make check`. It formats-checks, lints, and
tests every workspace member, validates both Compose examples, and checks the
tracked and staged diffs for whitespace errors. Plain `cargo build` and
`cargo test` also cover the complete workspace. Prefer `make run`; if you
bypass it for a real project command, run `cargo build --workspace --locked`
first so the CLI can find all three sibling plugin executables. Direct
`cargo run -p lightrail -- --help` is sufficient for CLI-only commands such as
help and version.

## Examples and live infrastructure

`make examples` validates example Compose files without contacting a provider.
The example READMEs describe how to copy one into a fresh Git repository; the
current checkout and current branch are always the deployed source, and no
GitHub remote is required.

Do not run a live cloud test without explicit authorization. Never place
provider tokens in arguments, files, commits, or logs. Use project-scoped
secret storage only after `lightrail init`, restrict SSH access to a narrow
operator CIDR, and run `doctor --target` plus `up --dry-run` before mutation.

Every live test must finish by checking the destruction plan, running
`down --all --yes`, confirming `status --all` finds nothing, and independently
confirming that no owned provider resources or temporary SSH keys remain.
`--all` is scoped to the selected profile's target and credentials, so repeat
that cleanup for every distinct target used by the test.
`--force` is only for teardown when the remote lock authority is unavailable;
it never bypasses a lock held by another operation.

## Change discipline

- Preserve stdout for command data and stderr for diagnostics and progress.
- Keep plugin stdout exclusively newline-delimited JSON-RPC.
- Keep committed configuration free of secret values and generated state.
- Do not edit a user's Compose files, Git worktree, branch, or global SSH
  configuration.
- Add focused regression tests for behavior changes and use stable,
  provider-independent tests by default.
