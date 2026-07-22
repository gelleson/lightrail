# Lightrail agent guide

This is the project-specific map for coding agents. Treat the repository as a
local orchestrator plus external executable plugins; do not infer a hosted
control plane, Git provider, registry, or remote Lightrail agent.

## Read before editing

Use these sources in order:

1. `README.md` for the implemented user workflow and current validation status.
2. `docs/product-spec.md` for behavioral invariants and explicit non-goals.
3. `docs/architecture.md` for ownership and lifecycle boundaries.
4. `docs/plugin-protocol.md` for the wire contract and trust model.
5. `CONTRIBUTING.md` for the local workflow and live-test safety.

The generic files under `.agents/` are reusable Rust guidance, not Lightrail
product documentation.

## Non-negotiable invariants

- The Git repository containing the current working directory and its checked
  out branch are the source. Do not fetch from GitHub, switch branches, or
  ignore dirty build-context files.
- Environment identity derives from project UUID, profile, and raw branch.
  Commit and dirty state affect the deployment revision, not environment
  identity. Local builds, resolved environment material, and file-backed
  assets may conservatively make a revision operation-scoped when their bytes
  cannot be represented safely and completely in provider-visible metadata.
- SSH/Hetzner and IP-addressed Kubernetes ingress hostnames remain
  `<branch>.<app>.<profile>.<project>.<8-hex-ip>.{sslip.io,nip.io}`. Branch
  comes before app. Fly uses one provider-native `<owned-app>.fly.dev`
  hostname per public app.
- Runtimes are remote. Literal localhost, loopback IPs, and hostnames resolving
  to loopback must fail during provider preflight, before mutation.
- Public apps use trusted HTTPS. SSH/Hetzner use Traefik and ACME HTTP-01;
  Kubernetes uses the selected existing IngressClass and cert-manager
  ClusterIssuer; Fly uses Fly Proxy and its native certificates. HTTP
  redirects to HTTPS on every provider.
- Only selected apps receive public routes. Other services stay private, and
  app ports are never published directly on a host.
- Core stays provider-independent. Infrastructure behavior belongs behind the
  versioned executable-plugin boundary.
- Plugin stdout is protocol-only newline-delimited JSON-RPC. Diagnostics go to
  stderr.
- Third-party plugins are explicitly installed and digest-pinned. Deployment
  never downloads them automatically or falls back to a same-named executable
  on `PATH`.
- Committed files contain secret references, never secret values. Resolve and
  send only the secrets declared for the active capability and operation.
- Never modify source Compose files. Resolve Compose into temporary or remote
  generated artifacts.
- A mutation follows inspect, ownership-scoped plan, authoritative lock,
  reinspection/continuity check, exact-plan apply, journal, and lock release.
- Every provider action that may mutate declares a supported exact inverse or
  `supported = false` with a safe reason. Omit rollback metadata only for
  genuinely side-effect-free work; retained Builder artifacts still declare
  their unsupported inverse explicitly.
- Failed `up` rolls back unless explicitly told to preserve resources.
  Destruction is confirmed, ownership-scoped, and idempotent.
- Kubernetes `up` is non-destructive: stale owned resources, new runtime
  resources on an established revision, and changed immutable Jobs require
  explicit `down` followed by `up`. Existing Traefik entrypoint names come
  from profile settings (`web`/`websecure` defaults); never rewrite the shared
  controller.
- Fly reconciles an existing service set in place, but adding or removing a
  Compose service changes the owned App aggregate and requires explicit
  `down` followed by `up`. Changes to named-volume topology, requested volume
  size, Machine region, or public-to-private exposure have the same boundary.
  Existing Machine updates have no exact automatic previous-revision inverse
  and must report rollback-incomplete on failure.
  Autostop/autostart applies only to Proxy-backed public services; private
  service Machines remain running under their restart policy.
- `down --force` is unavailable-lock recovery for machine-isolated provider
  deletion only. It never bypasses a busy lock or ownership checks.
- Generic SSH hosts and shared Traefik are retained during environment
  teardown. A Hetzner environment owns its machine and firewall. Kubernetes
  environments own namespaces but not clusters or shared ingress/cert
  controllers. Fly environments own exact Apps, Machines, volumes, and
  App-attached address/routing state; their custom 6PN name is not a separately
  deleted resource. Public web ingress is limited to 80/443 and SSH to
  configured operator CIDRs.
- Preserve cancellation, bounded subprocesses, kill-on-drop behavior,
  stdout/stderr separation, machine-readable output, and stable exit meaning.
- Kubernetes and Fly expiry defaults to 72 hours of provider-visible metadata,
  refreshed only by successful `up`. Cleanup requires explicit, feature-gated,
  exact-selection `prune`; there is no janitor. Pushed OCI images remain
  registry-managed cache after rollback, `down`, and `prune`.
- Usage reporting, tunnels, PR automation, cluster provisioning, shared
  Kubernetes setup, a background expiry janitor, custom DNS, remote exec, and
  native Windows remain deferred unless requested.

## Repository map

| Area | Start here |
| --- | --- |
| CLI flags, help, dispatch | `crates/lightrail/src/cli.rs` |
| Init and Compose discovery | `crates/lightrail/src/commands/init.rs`, `compose.rs` |
| Profiles | `crates/lightrail/src/commands/profile.rs` |
| Up, status, URLs, logs, down | `crates/lightrail/src/orchestrator.rs` |
| Views and output aggregation | `crates/lightrail/src/orchestrator/view.rs` |
| Plugin launch and pinning | `crates/lightrail/src/plugin_host.rs`, `plugin_registry.rs` |
| Project/config loading | `crates/lightrail/src/project.rs`, `workspace.rs` |
| Secrets | `crates/lightrail/src/secrets.rs`, `admin.rs` |
| Config and domain validation | `crates/lightrail-core/src/config.rs` |
| Git, identity, hostnames | `crates/lightrail-core/src/git.rs`, `identity.rs`, `naming.rs` |
| Protocol types and transport | `crates/lightrail-plugin-protocol/src/` |
| Compose/build/Traefik | `plugins/lightrail-plugin-compose/src/` |
| Generic SSH target | `plugins/lightrail-plugin-ssh/src/lib.rs`, `remote/` |
| Hetzner target | `plugins/lightrail-plugin-hetzner/src/{model,api,ssh,plugin}.rs` |
| Existing Kubernetes target | `plugins/lightrail-plugin-kubernetes/README.md`, then `src/` |
| Fly.io target | `plugins/lightrail-plugin-fly/README.md`, then `src/` |

The orchestrator owns ordering, retries, locks, journals, rollback, and
cross-plugin invariants. Plugins validate and execute capability-specific
plans. Provider/runtime labels plus committed configuration are authoritative;
`.lightrail/` is disposable local state.

## Development commands

Run `make help` for the canonical command surface. The normal gate is:

```console
make check
```

Useful inner-loop commands are:

```console
cargo check -p <package> --locked
cargo test -p <package> --locked
make run ARGS="--help"
```

Minimum test selection:

| Changed area | Minimum focused test |
| --- | --- |
| Core domain/config/Git/naming | `cargo test -p lightrail-core --locked` |
| Protocol | `cargo test -p lightrail-plugin-protocol --locked` |
| CLI/orchestrator/init | `cargo test -p lightrail --locked` |
| Compose/build/runtime | `cargo test -p lightrail-plugin-compose --locked` |
| Generic SSH | `cargo test -p lightrail-plugin-ssh --locked` |
| Hetzner | `cargo test -p lightrail-plugin-hetzner --locked` |
| Kubernetes | `cargo test -p lightrail-plugin-kubernetes --locked` |
| Fly.io | `cargo test -p lightrail-plugin-fly --locked` |
| Cross-cutting or release | `make check` |

Tests should not require real provider credentials or mutate live
infrastructure. Hetzner API tests bind a loopback mock server; restricted
sandboxes may require permission for those local-only checks.

## Live-test safety

- Never contact a real provider without explicit user authorization.
- Use a fresh repository copied from an example and a unique generated project
  ID. Never repurpose the Lightrail source repository as a deployment fixture.
- Never put credentials in command arguments, files, commits, patches, logs,
  tool output, or agent messages. Initialize before storing a project-scoped
  secret.
- Use an existing account SSH key only when authorized and restrict SSH ingress
  to the operator's `/32` or `/128`.
- Run `doctor --target` and `up --dry-run` before `up`. Do not use
  `--keep-failed` by default.
- Always clean up after success, failure, or cancellation:
  `down --all --dry-run`, `down --all --yes`, then `status --all`.
- `--all` covers only resources visible through the selected profile's target
  and credentials. Repeat cleanup for every distinct profile target.
- Independently verify that owned servers, firewalls, and temporary cloud SSH
  keys are gone. Use `--force` only after normal teardown fails specifically
  because the remote lock authority is unavailable.
- Do not modify the user's global `known_hosts`; use a scoped temporary file.

## Editing rules

- Preserve unrelated user changes and generated artifacts.
- Keep new modules cohesive; prefer leaf extractions over large rewrites of
  lifecycle code.
- Put protocol-compatible fields behind defaults and test old messages when
  evolving wire types.
- Update the durable contract when behavior changes. Keep dated smoke-test
  history in the README rather than copying it across specifications.
- Never commit `target/`, `.lightrail/`, credentials, temporary answer files,
  or copied live-test projects.
