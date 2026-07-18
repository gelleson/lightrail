# Lightrail

Lightrail is a Rust CLI for creating disposable, isolated branch environments
on remote infrastructure from the Git worktree already checked out on your
machine.

```console
$ git switch feature-login
$ lightrail up --profile preview

frontend  https://feature-login.frontend.preview.myproject.cb00710a.sslip.io
api       https://feature-login.api.preview.myproject.cb00710a.sslip.io

$ lightrail down --profile preview
```

Lightrail resolves Docker Compose locally, builds the current checkout with
Buildx, transfers missing images over SSH, deploys with Compose, and routes
each public app through Traefik with ACME HTTP-01. It does not require GitHub,
an image registry, a remote Lightrail daemon, or a central control plane.

> [!CAUTION]
> The CLI, protocol, and bundled Compose, SSH, and Hetzner plugins are
> implemented and covered by automated tests. The multi-app Hetzner path also
> completed a live end-to-end smoke test on 2026-07-18, including provisioning,
> local Buildx builds, SSH image transfer, Compose deployment, ACME HTTP-01,
> trusted HTTPS for both apps, repeated reconciliation, and normal teardown.
> A generic SSH host has not yet received the same live validation. Treat the
> current release as pre-production, especially for destructive operations.

## What is implemented

- The current Git worktree and current branch are the source of truth. Dirty
  files visible to Docker build contexts are included.
- Generic Ubuntu/Debian SSH hosts use project isolation; Hetzner Cloud uses a
  dedicated machine for each environment.
- Every runtime is remote. There is no localhost deployment mode; literal
  loopback targets and hostnames resolving to loopback are rejected before
  SSH.
- Compose services with `build:` are built locally for the target architecture
  and streamed over SSH when the remote image differs.
- Each selected app gets a stable HTTPS hostname:
  `<branch>.<app>.<profile>.<project>.<8-hex-ip>.sslip.io`.
- `nip.io` can be selected instead of `sslip.io`; no other DNS suffix is
  accepted.
- Shared Traefik listens on ports 80 and 443. Each environment has its own
  application network and its own ingress network; only public app containers
  join that ingress network.
- Repeated `up` reconciles the same branch environment. Plans, remote locks,
  bounded retries, journals, readiness checks, and best-effort rollback are
  implemented.
- `status --all` and `urls --all` aggregate every environment rediscovered for
  the project. Machine-isolated profiles fan out runtime inspection across
  labeled machines and retain a degraded summary when one cannot be reached.
- `down` is ownership-scoped and idempotent, including project-wide deletion
  of labeled Hetzner servers and firewalls. `down --force` may bypass only an
  unreachable machine-isolated remote lock authority; it never bypasses a
  lock held by another operation and still requires destructive confirmation.
- Ctrl+C during `up` or `down` sends semantic cancellation to the active
  plugin and waits for its safe stopping point. A cancelled `up` then follows
  the normal rollback path unless `--keep-failed` was selected.
- Application secret references are resolved and sent to the Compose runtime
  only as part of `up` (including its possible rollback); explicitly declared
  provider credentials are still supplied to the provider operations that
  require them.
- Infrastructure capabilities are external executable plugins using versioned
  newline-delimited JSON-RPC over stdin/stdout. Third-party executables are
  checked against their pinned ID, version, protocol, source, and SHA-256
  digest before launch. Bundled plugins are loaded only from trusted absolute
  sibling/development paths and never from a same-named executable on `PATH`.

## Getting started

The workspace requires Rust 1.85 or newer. Runtime prerequisites are Git,
Docker with Compose and Buildx, and an OpenSSH-compatible client.

Build the CLI and all three bundled plugin executables:

```console
cargo build --workspace
target/debug/lightrail doctor
```

Place `target/debug` on `PATH`, or use absolute paths to `lightrail` and its
sibling plugin executables when running it from another repository.

Run the following inside a Git repository whose root contains a Compose file:

```console
lightrail init
lightrail up --dry-run
lightrail up
lightrail urls
lightrail logs --follow
lightrail down
```

`init` discovers Compose services and ports, asks for the first profile, and
writes `lightrail.toml`, `lightrail.lock`, and a `.lightrail/` ignore entry.
It refuses to replace an existing configuration unless `--force` is supplied.
Use `lightrail doctor --target` after initialization to inspect the configured
target as well as local tools.

### Non-interactive SSH initialization

An SSH answers file needs `settings.target.host`. It also needs
`public_ipv4` when `host` is a DNS name or is not itself the public IPv4 used
by `sslip.io`/`nip.io`.

```toml
# answers-ssh.toml
project_slug = "myproject"
compose = ["compose.yaml"]
target = "ssh"
isolation = "project"
dns_domain = "sslip.io"

[[apps]]
name = "frontend"
service = "web"
port = 3000

[settings.target]
host = "server.example.com"
user = "deploy"
public_ipv4 = "1.2.3.4" # replace with the host's public IPv4
bootstrap = "auto"
```

```console
lightrail init --from answers-ssh.toml
```

If `host` is already a publicly routable IPv4, omit `public_ipv4`. Optional
SSH target settings include `port`, absolute `identity_file` and
`known_hosts_file` paths, `remote_root`, `bootstrap = "auto" | "install" |
"verify"`, and `sudo = "auto" | "required" | "never"`.

### Non-interactive Hetzner initialization

Hetzner initialization requires at least one existing Hetzner SSH key name or
ID and explicit, non-world-open operator CIDRs. Use a narrow `/32` or `/128`
where possible.

```toml
# answers-hetzner.toml
project_slug = "myproject"
compose = ["compose.yaml"]
target = "hetzner"
isolation = "machine"
dns_domain = "nip.io"

[[apps]]
name = "frontend"
service = "web"
port = 3000

[[apps]]
name = "api"
service = "api"
port = 8080
health_path = "/health"
health_status = 200

[settings.target]
server_type = "cx23"
location = "nbg1"
ssh_keys = ["my-hetzner-key"]
allowed_ssh_cidrs = ["198.51.100.42/32"] # replace with your operator CIDR
```

```console
lightrail init --from answers-hetzner.toml
lightrail secret set hetzner-token
lightrail up --dry-run
```

The generated configuration contains only a reference to `hetzner-token`; the
value is stored outside committed configuration.

## Examples

The repository includes copy-ready Compose projects for two common application
shapes:

- [`examples/single-app`](examples/single-app) exposes one `hello` app.
- [`examples/multi-app`](examples/multi-app) exposes separate `frontend` and
  `api` branch subdomains.

Each example includes generic SSH and Hetzner init-answer templates. Copy an
example into its own Git repository before running it so Lightrail uses that
repository's current branch; no GitHub remote is required.

## Commands

Global options are `--profile <name>`, `--output human|json|plain`, and
`--verbose`/`-v`.

```text
lightrail init [--from <answers.toml>] [--non-interactive] [--profile <name>] [--force]
lightrail profile add <name>|list|show <name>|remove <name>
lightrail up [--dry-run] [--keep-failed] [--lock-timeout <30s|2m>]
lightrail status [--all]
lightrail urls [--all]
lightrail logs [service] [--follow] [--tail <count>]
lightrail down [--all] [--dry-run] [--yes] [--force] [--lock-timeout <30s|2m>]
lightrail doctor [--target]
lightrail secret set <name> [--stdin]|list|delete <name>
lightrail plugin install <path-or-https-url>|sync|list|inspect <id>|update <id>|remove <id>
lightrail completion <shell>
lightrail version
```

`version` prints the CLI release version. The protocol version is defined by
the protocol crate; `plugin inspect` shows manifests for installed,
third-party pinned plugins.

Usage/cost reporting, remote `exec`, authenticated tunnels, PR-provider
automation, Fly.io, Kubernetes, k3s, custom DNS, and native Windows are not
implemented.

See [the product specification](docs/product-spec.md),
[the architecture](docs/architecture.md), and
[the plugin protocol](docs/plugin-protocol.md) for the complete contracts.

## Development

```console
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
