# Lightrail

Lightrail is a Rust CLI for creating disposable, isolated branch environments
on remote infrastructure from the Git worktree already checked out on your
machine.

```console
$ git switch feature-login
$ lightrail up --profile preview

Plan: up feature-login / preview
  - ...
feature-login / preview  ready
  frontend         https://feature-login.frontend.preview.myproject.cb00710a.sslip.io
  api              https://feature-login.api.preview.myproject.cb00710a.sslip.io

$ lightrail down --profile preview
```

Lightrail resolves Docker Compose locally and builds the current checkout with
Buildx. SSH and Hetzner profiles transfer missing images and deploy with
Compose; Kubernetes profiles push images to an OCI registry and deploy native
workloads to an existing cluster; Fly profiles deploy agentlessly through the
Fly APIs. It does not require GitHub, a remote Lightrail daemon, or a central
control plane.

> [!CAUTION]
> The CLI, protocol, and bundled Compose, SSH, Hetzner, Kubernetes, and Fly
> plugins are covered by automated tests. The multi-app Hetzner path also
> completed a live end-to-end smoke test on 2026-07-18, including provisioning,
> local Buildx builds, SSH image transfer, Compose deployment, ACME HTTP-01,
> trusted HTTPS for both apps, repeated reconciliation, and normal teardown.
> Generic SSH, Kubernetes, and Fly have not received the same live validation.
> In particular, no live Rackspace Spot cluster or Fly account is covered by
> that historical result. Treat the current release as pre-production,
> especially for destructive operations.

## What is implemented

- The current Git worktree and current branch are the source of truth. Dirty
  files visible to Docker build contexts are included.
- Generic Ubuntu/Debian SSH hosts use project isolation; Hetzner Cloud uses a
  dedicated machine for each environment. Existing Kubernetes clusters and
  Fly use provider-native environment isolation.
- Every runtime is remote. There is no localhost deployment mode; literal
  loopback SSH targets and selected Kubernetes API hosts resolving to loopback
  are rejected before mutation.
- Compose services with `build:` are built locally for the target architecture.
  SSH/Hetzner stream missing images over SSH; Kubernetes/Fly push deterministic
  references to the configured provider-reachable registry. Pushed images are
  retained as build cache when an environment is destroyed.
- Local build paths and file-backed Compose assets must resolve inside the
  current Git root, including through symbolic links. Revisions use portable
  project-relative paths. Local builds, resolved environment material, and
  file-backed assets receive an operation-scoped revision so their bytes can
  reconcile without putting secret-derived hashes in provider metadata.
- Each selected app gets a discoverable HTTPS endpoint. SSH and Hetzner use
  `<branch>.<app>.<profile>.<project>.<8-hex-ip>.sslip.io` (or `nip.io`).
  Kubernetes reads the exact configured ingress-controller LoadBalancer
  Service and uses the same hexadecimal-IP DNS form for its public IPv4
  address; Fly uses its native `fly.dev` endpoint.
- SSH/Hetzner use Traefik on ports 80 and 443; generic SSH shares that
  Traefik instance across environments. Each Compose environment has its own
  application and ingress networks, and only public app containers join the
  ingress network.
- Kubernetes uses ordinary namespaces, workloads, Services, persistent volume
  claims, and Ingress resources. It requires an existing kube context,
  supported NGINX or Traefik `IngressClass`, exact LoadBalancer Service backing
  that class, control namespace for Lease locks, registry, and any required
  cert-manager issuer or image-pull Secret selected by the profile. Lightrail
  does not create clusters, nodes, ingress controllers, issuers, or registries.
- Fly uses Lightrail-owned Apps, Machines, volumes, Fly Proxy, and native
  endpoints. It has no remote Lightrail agent.
- Repeated `up` reconciles the same branch environment. Plans, remote locks,
  bounded retries, journals, readiness checks, and best-effort rollback are
  implemented.
- Kubernetes/Fly resources remain isolated per environment, while every
  mutation for one immutable project is serialized through one provider-backed
  project lock. This deliberately prevents concurrent branch mutations on the
  same selected cluster/account boundary.
- `status --all` and `urls --all` aggregate every project environment visible
  through the selected profile's configured target. Machine-isolated profiles
  fan out runtime inspection across labeled machines and retain a degraded
  summary when one cannot be reached.
- `down` is ownership-scoped and idempotent, including deletion of all
  project-labeled Hetzner servers and firewalls visible to the selected
  profile's target credentials. `down --force` may bypass only an unreachable
  machine-isolated remote lock authority; it never bypasses a lock held by
  another operation and still requires destructive confirmation.
- Ctrl+C during `up`, `down`, or `prune` sends semantic cancellation to the
  active plugin and waits for its safe stopping point. A cancelled `up` then
  follows the normal rollback path unless `--keep-failed` was selected.
- Application secret references are resolved and sent only to the selected
  runtime as part of `up` (including a possible rollback). Compose and
  Kubernetes consume that narrow path; Fly currently rejects app secret
  references. Explicit provider credentials are supplied only to provider
  operations that require them.
- Infrastructure capabilities are external executable plugins using versioned
  newline-delimited JSON-RPC over stdin/stdout. Third-party executables are
  checked against their pinned ID, version, protocol, source, and SHA-256
  digest before launch. Bundled plugins are loaded only from trusted absolute
  sibling/development paths and never from a same-named executable on `PATH`.
- Kubernetes and Fly refresh provider-visible expiry metadata from
  `ttl_hours` on every successful `up`. `lightrail prune` discovers only
  expired environments owned by the current project, shows the exact set,
  confirms, takes a project lock, reinspects the same set, and invokes only a
  capability-gated exact-selection destroy contract.
- Tunnels/private exposure, usage reporting, cluster provisioning, shared
  Kubernetes component installation, and a `setup` command are not
  implemented.

## Getting started

### Quick Installation (One-liner)

Install the CLI and all bundled plugins into `~/.local/bin` using the bash installer:

```console
curl -fsSL https://raw.githubusercontent.com/gelleson/lightrail/main/install.sh | sh
```

You can customize the destination or target version using environment variables:

```console
PREFIX=/usr/local VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/gelleson/lightrail/main/install.sh | sh
```

### Building from source

The workspace requires Rust 1.85 or newer. Common runtime prerequisites are
Git and Docker with Compose and Buildx. SSH/Hetzner also require an
OpenSSH-compatible client; Kubernetes requires `kubectl` and access to the
configured existing context.

Build the CLI and all five bundled plugin executables:

```console
cargo build --workspace
target/debug/lightrail doctor
```


Place `target/debug` on `PATH`, or use absolute paths to `lightrail` and its
sibling plugin executables when running it from another repository.

Run the following inside a Git repository whose root contains a Compose file:

```console
lightrail init
lightrail doctor --target
lightrail up --dry-run
lightrail up
lightrail down
```

`init` discovers Compose services and ports, creates a `preview` profile by
default (`-p <name>` chooses another), and writes `lightrail.toml`,
`lightrail.lock`, and a `.lightrail/` ignore entry.
It refuses to replace an existing configuration unless `--force` is supplied.
Destroy any live environments before using `--force` to change or remove
profiles or targets; the project ID is preserved so owned resources remain
discoverable.
`up` performs preflight checks and prints each app URL. Use `up --dry-run` to
inspect the plan, `doctor --target` for an explicit prerequisite check,
`lightrail -o plain urls` for one raw URL per line, and, on SSH/Hetzner
Compose profiles, `logs --follow` while debugging. `logs -o json` emits one
compact JSON object per line when the selected runtime supports logs.

### One predictable workflow

Lightrail has no repository or branch argument. The Git worktree containing
the current directory supplies the source, and its checked-out branch supplies
the environment identity. A profile supplies the reusable deployment policy.
That keeps the normal human and coding-agent loop small:

```console
git status --short --branch
lightrail doctor --target
lightrail up --dry-run
lightrail up
lightrail -o plain urls
lightrail status
lightrail down --dry-run
lightrail down --yes
```

Do not switch branches on behalf of an existing worktree operation. To work on
another branch independently, run Lightrail from that branch's own Git
worktree. For automation, prefer `-o json` when consuming status or plan data
and `-o plain urls` when only URLs are needed; command data stays on stdout
while progress and diagnostics stay on stderr. Committed `lightrail.toml` and
`lightrail.lock` are the portable intent. `.lightrail/` is disposable local
state.

Human mutation commands print their authoritative plan before applying it.
JSON/plain mutation commands reserve stdout for one final machine-readable
result, so automation should run the matching `--dry-run` first to capture and
review the plan, then run the real command (with `--yes` for destruction).

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

The SSH/Hetzner Compose runtime accepts only the normalized implicit `default`
network. Custom, external, aliased, static, and multiple-network semantics fail
before remote mutation. Named volumes must use Compose's generated name and no
custom driver/options; file-backed Compose configs and secrets must stay inside
the granted Git root. Generated checkout-dependent names are replaced with
environment-scoped names on the target.

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
value is stored outside committed configuration. In headless CI, provide it
through the CI secret variable `LIGHTRAIL_SECRET_HETZNER_TOKEN` instead. In
general, `LIGHTRAIL_SECRET_` is followed by the uppercased secret name with
non-alphanumeric characters replaced by `_`.

### Existing Kubernetes cluster

Kubernetes initialization never creates or resizes a cluster. A
non-interactive answer file must name an existing context, an OCI registry and
repository prefix reachable by the cluster, one existing NGINX or Traefik
`IngressClass`, and the exact LoadBalancer Service backing that class:

```toml
# answers-kubernetes.toml
project_slug = "myproject"
compose = ["compose.yaml"]
target = "kubernetes"
isolation = "environment"
dns_domain = "sslip.io"

[[apps]]
name = "frontend"
service = "web"
port = 3000

[settings.target]
context = "rackspace-spot"
kubeconfig = "/home/me/.kube/config" # optional; must be absolute
registry = "ghcr.io"
repository = "my-team/previews"
ingress_class = "nginx"
ingress_service_namespace = "ingress-nginx"
ingress_service_name = "ingress-nginx-controller"
control_namespace = "lightrail-system"
cluster_issuer = "letsencrypt"
# image_pull_secret = "registry-pull"
```

The control namespace, RBAC, ingress controller, exact LoadBalancer Service,
and configured cert-manager `ClusterIssuer` must already exist; the issuer
must report Ready and contain an HTTP-01 solver. A configured image-pull
Secret must be made available in each new environment namespace by existing
cluster policy;
Lightrail does not copy registry credentials. If several ingress classes
exist, the committed `ingress_class`, `ingress_service_namespace`, and
`ingress_service_name` are authoritative; Lightrail never guesses or edits an
existing controller. Authenticate local Docker to the push registry and
separately ensure cluster pull access. A configured Service that reports only
a provider hostname is not assumed to be a delegated wildcard DNS zone; the
generic plugin currently requires a public ingress IPv4 for its
`sslip.io`/`nip.io` route.

The native translator fails on non-empty service fields it cannot preserve,
including host networking, privileged containers, local bind mounts, and
Compose `configs`/`secrets`; every service needs `build:` or `image:`. It
accepts only Compose's normalized implicit `default` network. Custom or
external network semantics and external, custom-named, or driver-configured
volumes are rejected. Build contexts and explicit Dockerfiles must resolve
inside the operation context's granted Git root, including through symbolic
links. Revision input normalizes those paths across checkout directories, but
local-build tags remain operation-scoped because ignored files may still enter
Docker's context; Buildx layer caching remains available. Resolved environment
values are removed before revision hashing. Use app environment secret
references for generated Kubernetes Secret values. A named-volume service
becomes stateful; explicit Compose extensions
`x-lightrail: { kind: job }` and `x-lightrail: { kind: stateful }` opt into
those workload forms. Every non-Job service receives private cluster DNS; a
portless service uses a selector-backed headless Service without a guessed
port. Completed Jobs are retained without a Job TTL until teardown.
Unchanged image-only Jobs are repeatable; an existing local-build Job requires
`down` then `up` on every later operation because its conservative
operation-scoped image revision changes the immutable Job spec.
Long-running workloads using generated environment Secrets receive a
non-secret operation-derived Pod-template revision on each `up`, so changed
values reach Pods without putting secret-derived hashes in metadata. Generated
Secret values persist in the Kubernetes API; cluster RBAC and etcd encryption
remain the cluster operator's responsibility.
Public NGINX Ingresses receive explicit SSL-redirect annotations. For Traefik,
Lightrail verifies a supported Middleware CRD and creates an environment-owned
RedirectScheme Middleware; it never edits the shared controller. Other
IngressClass controller types fail validation before render.
Traefik profiles default to existing entrypoints named `web` and `websecure`;
set `traefik_http_entrypoint` and `traefik_https_entrypoint` when the selected
controller uses different, distinct names.

Native `up` is deliberately non-destructive. If the desired Compose model
removes an owned Kubernetes resource, adds a runtime resource to an established
revision, or changes an existing Job, Lightrail stops with instructions to run
`lightrail down` and then `lightrail up`. Existing Deployment and StatefulSet
mutations are deliberately marked non-reversible because retaining full live
manifests could retain injected secret-bearing fields. If a later phase fails,
their runtime update is reported as rollback-incomplete. Initial namespace
cleanup and exact Exposure and DNS-expiry inverses remain supported.

Optional target settings include absolute `kubeconfig`, `namespace_prefix`,
`dns_domain = "sslip.io"|"nip.io"`, `image_pull_secret`, `platforms`,
`replicas`, `ttl_hours`, `traefik_http_entrypoint`,
`traefik_https_entrypoint`,
`command_timeout_seconds`, and `readiness_timeout_seconds`. Expiry metadata is
refreshed by `up`, and `ttl_hours` defaults to 72. Run
`lightrail prune --dry-run` to review environments whose deadline has passed,
then `lightrail prune --yes` to remove that exact owned set. Use ordinary
`down` for deterministic cleanup of the current branch; `prune` is
project-wide expiry cleanup within the selected provider boundary.
`lightrail -o json prune --dry-run` emits one machine-readable plan document.
An empty `platforms` list discovers Ready, schedulable Linux node
architectures. Explicit values must be a subset of that set and constrain both
the image build and Pod scheduling, using a node selector for one architecture
or required node affinity for several.

### Fly.io

Fly profiles use the native API and `fly.dev` endpoints:

```toml
# answers-fly.toml
project_slug = "myproject"
compose = ["compose.yaml"]
target = "fly"
isolation = "environment"

[[apps]]
name = "frontend"
service = "web"
port = 3000

[settings.target]
organization = "personal"
region = "iad" # optional
registry = "registry.fly.io"
platform = "linux/amd64"
app_prefix = "lr"
cpu_kind = "shared"
cpus = 1
memory_mb = 256
auto_stop = true
ttl_hours = 72
lock_ttl_seconds = 3600
volume_size_gb = 3
```

The generated profile references `fly-token`; store it with `lightrail secret
set fly-token` or provide `LIGHTRAIL_SECRET_FLY_TOKEN` in CI. Lightrail creates
one Fly App per Compose service. All Apps in the environment join the same
deterministic custom 6PN membership boundary; this is not a separately managed
network resource. Only selected public services receive a shared IPv4 and Fly
Proxy routing. Local Buildx pushes to `registry.fly.io` using the token in an
isolated temporary Docker configuration, then resolves built tags to immutable
digests for the Machines. External `image:` references remain as configured.
`down` deletes the exact owned Machines, volumes, and Apps; App-attached
address/routing state disappears with its App. Registry images and the shared
project lock App remain.

The current Fly translator permits at most one named volume per service
Machine; `region` is required when any service uses one, and `volume_size_gb`
applies when that volume is first created rather than resizing it later. It
rejects bind/external volumes, host networking, privileged services,
`env_file`, Compose `configs`/`secrets`, and unsupported service/deploy fields.
Every service needs `build:` or `image:`; application secret references are
not yet supported. Compose `command`/`entrypoint`, when set, must use list
form. A Compose `healthcheck` is accepted as source metadata and remains part
of the revision, but is not translated to a Fly Machine check. Lightrail app
`health_path`, `health_status`, `health_interval_seconds`, and
`health_timeout_seconds` are authoritative; `health_status` must be in the 2xx
range. Private services receive no public Fly service or check. Fly
`auto_stop`/autostart is a Proxy-service behavior for public services; private
service Machines have no Proxy wake trigger and remain running under their
restart policy, so include them in cost estimates. The current plugin supports
exactly one Machine per service. Once an environment exists, adding or removing
a Compose service changes its owned Fly App set and therefore requires explicit
`lightrail down` followed by `lightrail up`. Changing named-volume topology or
the requested volume size, changing Machine region, or making a previously
public service private has the same requirement; ordinary in-place service
revisions keep the same Apps. A failed update to an existing Machine has no exact
previous-revision inverse and is reported as rollback-incomplete. Private
service discovery uses each deterministic Fly App name beneath `.internal`,
not the original Compose service alias. Fly uses the same explicit `prune`
workflow and defaults `ttl_hours` to 72. Fly log retrieval is not implemented
in this slice; Kubernetes supports historical logs but not `--follow`.

Detailed provider contracts and implementation maps live in the
[Kubernetes plugin guide](plugins/lightrail-plugin-kubernetes/README.md) and
[Fly plugin guide](plugins/lightrail-plugin-fly/README.md).

## Examples

The repository includes copy-ready Compose projects for two common application
shapes:

- [`examples/single-app`](examples/single-app) exposes one `hello` app.
- [`examples/multi-app`](examples/multi-app) exposes separate `frontend` and
  `api` branch subdomains.

Each example includes init-answer templates for generic SSH, Hetzner, an
existing Kubernetes cluster, and Fly. Copy an example into its own Git
repository before running it so Lightrail uses that repository's current
branch; no GitHub remote is required.

## Commands

Global options are `--profile`/`-p <name>`,
`--output`/`-o human|json|plain`, and `--verbose`/`-v`.

```text
lightrail init [--from <answers.toml>] [--target ssh|hetzner|kubernetes|fly] [--domain sslip.io|nip.io] [--profile <name>] [--force]
lightrail profile add <name> [--from <profile>]|list|show <name>|remove <name>|default <name>
lightrail up [-n|--dry-run] [--keep-failed] [--lock-timeout <30s|2m>]
lightrail status [-a|--all]
lightrail urls [-a|--all]
lightrail logs [service] [--follow] [--tail <count>]
lightrail down [-a|--all] [-n|--dry-run] [--yes] [--force] [--lock-timeout <30s|2m>]
lightrail prune [-n|--dry-run] [--yes] [--lock-timeout <30s|2m>]
lightrail doctor [--target]
lightrail secret set <name> [--stdin]|list|delete <name>
lightrail plugin install <path-or-https-url>|sync|list|inspect <id>|update <id>|remove <id>
lightrail completion <shell>
lightrail version
```

`version` prints the CLI release version. The protocol version is defined by
the protocol crate; `plugin inspect` shows manifests for installed,
third-party pinned plugins. Plugin commands run inside an initialized project
and update that project's `lightrail.lock`.

`--all` is target-scoped: it covers every project environment the selected
profile's configured target and credentials can rediscover. Repeat it for each
distinct profile target, then verify each provider or host independently.
`prune` has the same selected context/account boundary and skips entries
without provider expiry metadata; it never substitutes an unscoped
`down --all`.

Usage/cost reporting, remote `exec`, authenticated tunnels, PR-provider
automation, cluster provisioning, shared-component setup commands, custom
DNS-provider APIs, and native Windows are not implemented.

See [the product specification](docs/product-spec.md),
[the architecture](docs/architecture.md), and
[the plugin protocol](docs/plugin-protocol.md) for the complete contracts.

## Development

```console
make help
make check
make build-fast       # Fast optimized compilation profile
make static           # Fully static binary build (crt-static)
make release V=1      # Verbose release build
```

The Makefile builds and tests the CLI plus every bundled plugin; plain Cargo
workspace commands do the same. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
human workflow, fast/static build options, release tagging cycle, and
[AGENTS.md](AGENTS.md) for the project map and invariants used by coding agents.
