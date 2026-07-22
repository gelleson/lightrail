# Contributing to Lightrail

Lightrail keeps its local workflow deliberately small: Rust with Rustfmt and
Clippy, Docker, Git, and GNU Make are enough to build and verify the whole
repository. Provider-specific manual work adds only the corresponding client.

## Start here

Install Rust 1.85 or newer, Git, Docker with Compose and Buildx, and an
OpenSSH-compatible client. Install `kubectl` as well when exercising the
existing-cluster Kubernetes plugin. Then run:

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
- `plugins/lightrail-plugin-kubernetes` owns local registry builds and native
  deployment to an explicitly selected existing cluster.
- `plugins/lightrail-plugin-fly` owns agentless Fly Apps, Machines, volumes,
  native routes, and provider locks.
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
cargo test -p lightrail-plugin-kubernetes --locked
cargo test -p lightrail-plugin-fly --locked
```

Before handing off any change, run `make check`. It formats-checks, lints, and
tests every workspace member, validates both Compose examples, and checks the
tracked and staged diffs for whitespace errors. Plain `cargo build` and
`cargo test` also cover the complete workspace. Prefer `make run`; if you
bypass it for a real project command, run `cargo build --workspace --locked`
first so the CLI can find all five sibling plugin executables. Direct
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

For Kubernetes, use a fresh copied example with a unique generated project ID
and an explicitly reviewed context. Never create/delete a cluster or node, or
install/modify shared RBAC, ingress, certificate, registry, or storage
components as part of a Lightrail live test. Do not edit the user's global
kubeconfig; pass an absolute scoped file when isolation is needed. Verify the
existing NGINX/Traefik IngressClass, control namespace/Lease permissions,
registry push, cluster policy that supplies any configured image-pull Secret,
and public ingress IPv4 before `up`. Verify that the required ClusterIssuer is
Ready and includes an HTTP-01 solver; for Traefik, verify one supported
Middleware CRD plus the configured HTTP/HTTPS entrypoint names. Do not turn an
`up` into a destructive Kubernetes replacement: stale resources, additions to
an established runtime topology, and changed Jobs must keep the explicit
`down` then `up` recovery.

For Fly, use an explicitly authorized organization and the project-scoped
`fly-token` reference. Expect one App per Compose service, environment-scoped
custom 6PN membership (not a separately deleted network resource), Machines,
optional volumes, and public Apps only where the profile selected them. The
project lock App is shared control state and is retained after environment
cleanup.

Every live test must finish by checking the destruction plan, running
`down --all --yes`, confirming `status --all` finds no environment, and
independently confirming that no environment-owned provider resources or
temporary SSH keys remain. Kubernetes shared cluster components, the Fly lock
App, and pushed registry images are intentionally retained. Registry
retention/garbage collection follows the registry's policy.
`--all` is scoped to the selected profile's target and credentials, so repeat
that cleanup for every distinct target used by the test.
`--force` is only for teardown when the remote lock authority is unavailable;
it never bypasses a lock held by another operation and is unavailable for
Kubernetes/Fly. When testing expiry, run `prune --dry-run` first and verify
the exact candidate IDs; do not use prune as a substitute for deterministic
end-of-test cleanup.

## Change discipline

- Preserve stdout for command data and stderr for diagnostics and progress.
- Keep plugin stdout exclusively newline-delimited JSON-RPC.
- Keep committed configuration free of secret values and generated state.
- Do not edit a user's Compose files, Git worktree, branch, or global SSH
  configuration.
- Do not edit a user's global kubeconfig or rely on an implicit Kubernetes
  context in destructive tests.
- Add focused regression tests for behavior changes and use stable,
  provider-independent tests by default.
