# Lightrail product specification

Status: implemented local-first contract. The CLI, protocol, and bundled
Compose, SSH, Hetzner, Kubernetes, and Fly plugins are present and covered by
automated tests. See the README for current live-validation status; this
document intentionally keeps the behavioral contract independent of dated
smoke-test results.

This document turns the product interview into a durable behavioral
specification. “Must” describes an MVP invariant. Where the current
implementation deliberately differs from the broader product contract, this
document calls out the limitation.

## 1. Product definition

Lightrail is a Rust command-line tool that turns the repository and Git
checkout containing the user's current working directory into an isolated,
remote, HTTPS-accessible environment.

It is intended for branch previews, pull-request-style environments, and
temporary integration environments without requiring a Git hosting provider.
It builds locally, deploys remotely, and remains agentless: the remote system
runs ordinary infrastructure components such as Docker/Compose/Traefik,
Kubernetes workloads, or Fly Machines, but no Lightrail daemon.

### 1.1 MVP goals

The MVP must:

1. Create reusable, named deployment profiles with `lightrail init`.
2. Treat the current Git worktree and branch as the source revision.
3. Build Compose services locally and deploy them to generic SSH, Hetzner,
   existing Kubernetes, or Fly targets.
4. Expose several apps in one project at separate, predictable HTTPS
   subdomains.
5. Isolate environments as separate Compose projects on a shared host,
   dedicated machines, or provider-native namespaces/application groups.
6. Reconcile repeated deployments, verify readiness, and automatically roll
   back failed changes where possible.
7. Rediscover environments from provider and runtime metadata without a
   central service or indispensable local state.
8. Make infrastructure capabilities replaceable through external executable
   plugins.
9. Destroy every resource owned by an environment safely and idempotently.
10. Work interactively for developers and non-interactively for CI.

### 1.2 MVP non-goals

The following are not part of the MVP:

- local or localhost runtime environments;
- GitHub, GitLab, or pull-request API integration;
- building a branch that is not the current checkout;
- switching branches or editing the user's worktree;
- private tunnel exposure;
- provisioning, resizing, or deleting Kubernetes clusters or nodes;
- installing or upgrading shared Kubernetes ingress, certificate, registry,
  or RBAC components through a `setup` command;
- custom DNS zones or DNS-provider APIs;
- raw public TCP or UDP services;
- user-selectable blue/green, canary, or advanced rollout strategies;
- remote shell execution;
- a usage or cost-reporting command;
- native Windows support;
- a central control plane, hosted service, or remote Lightrail agent;
- automatic third-party plugin downloads during deployment;
- a central plugin marketplace;
- restoration of application data changed by a failed revision.

The architecture must leave clear extension points for these future
capabilities without pretending they are available now. Kubernetes support
connects only to an existing cluster; Fly support remains agentless.

## 2. Domain model and invariants

### 2.1 Project

A project is defined by a committed `lightrail.toml` at the repository project
root. It has:

- an immutable generated project ID used for ownership and discovery;
- a human-readable DNS-safe project slug;
- one or more Compose input files;
- named apps;
- named profiles;
- one default profile.

Renaming the project slug changes future hostnames but must not change the
project's ownership identity.

### 2.2 Profile

A profile is a reusable deployment policy, such as `preview` or `staging`. It
selects:

- isolation mode (`project`, `environment`, or `machine`);
- public apps;
- source, builder, target, runtime, exposure, and DNS plugins;
- settings owned and validated by those plugins.

Profiles are created during `init` and can be managed later with the `profile`
subcommands.

### 2.3 App

An app is a named, public HTTP service mapped to:

- exactly one Compose service; and
- exactly one internal container port.

A project may contain many apps. Each app receives its own hostname. Compose
services that are not selected as apps—including databases, queues, caches,
workers, and internal APIs—remain private unless explicitly selected in the
profile.

### 2.4 Environment

An environment is the deterministic combination of:

- immutable project ID;
- selected profile; and
- current Git branch identity.

The same project, profile, and branch always refer to the same environment.
`up` reconciles it rather than creating a duplicate. Dirty worktree content and
new commits create new revisions of that environment; they do not create new
environment identities or hostnames.

### 2.5 Revision

A revision is a SHA-256 digest of normalized desired state and the locally
resolved Compose document. It selects deterministic tags for locally built
images and generated deployment material. The remote manifest records the
observed IDs and repository digests of deployed images. The previous healthy
generated documents are retained sufficiently to support best-effort
application rollback.

For the SSH/Hetzner Compose runtime, canonical revision input removes the
checkout root and ephemeral resolved-file path, represents Compose files,
build contexts, Dockerfiles, and file-backed configs/secrets relative to the
granted Git root, and normalizes Compose-generated project, default-network,
and volume names. Resolved service environment values and explicit
profile/app environment literal values are reduced to non-secret key/reference
shape. Any local build, resolved or explicit environment, or file-backed asset
makes the revision operation-scoped. This preserves Buildx cache reuse and
forces each affected `up` to reconcile without deriving provider-visible
metadata from environment or asset plaintext.

Persistent volume contents, database mutations, and historical secret values
are not revisions and are not rollback-capable.

OCI images pushed for Kubernetes or Fly are immutable build artifacts/cache,
not environment runtime resources. Normal environment destruction does not
delete them.

### 2.6 Environment expiry

Environment-isolated Kubernetes and Fly profiles define `ttl_hours`, default
72. A successful `up` refreshes a provider-visible expiry deadline for that
environment. Expiry is metadata, not an automatic deletion timer:
`lightrail prune` must still inspect, plan, confirm, lock, re-inspect, and
delete the exact expired set.

## 3. Current-working-directory and Git semantics

All environment commands resolve the Git worktree containing the current
working directory. Lightrail must not require a GitHub or GitLab remote.

For `up`:

- The current checkout is the only source tree.
- The currently checked-out branch determines environment identity and the
  branch hostname label.
- Tracked, staged, untracked, and otherwise uncommitted files visible to the
  Docker build context are included normally. Lightrail does not create a
  hidden clean checkout.
- Lightrail must not switch branches, fetch a branch, or accept a different
  branch as the build source.
- A Git worktree is naturally a separate source directory. Running from two
  worktrees can therefore operate on two branch environments concurrently.
- In detached HEAD state, the branch identity is
  `sha-<first-12-lowercase-hex-characters-of-commit>`.
- Repeated `up` from the same worktree branch updates the existing
  environment.

Branch names are inputs to DNS normalization; they do not need to already be
DNS-safe.

Profile selection precedence is:

1. `--profile <name>`;
2. `LIGHTRAIL_PROFILE`;
3. `project.default_profile` in `lightrail.toml`.

## 4. Configuration

### 4.1 Files and ownership

- `lightrail.toml` is committed and contains project, app, profile, plugin, and
  secret-reference configuration.
- `lightrail.lock` is committed and pins third-party plugins; it is valid and
  normally empty when only bundled plugin IDs are selected.
- `.lightrail/` is ignored and currently contains replaceable operation
  journals and a secret-name index, never secret values.
- Original Compose files must never be modified.
- Configuration schema upgrades must be explicit. Lightrail must not silently
  rewrite committed configuration.

### 4.2 Example

```toml
schema = 1

[project]
id = "018f6f9f-21aa-7da8-a1b2-31da91ed5148"
slug = "myproject"
compose = ["compose.yaml"]
default_profile = "preview"

[apps.frontend]
service = "frontend"
port = 3000

[apps.api]
service = "api"
port = 8080
health_path = "/health"
health_status = 200

[profiles.preview]
isolation = "machine"
apps = ["frontend", "api"]

[profiles.preview.pipeline]
source = "dev.lightrail.compose"
builder = "dev.lightrail.compose"
target = "dev.lightrail.hetzner"
runtime = "dev.lightrail.compose"
exposure = "dev.lightrail.compose"
dns = "dev.lightrail.compose"

[profiles.preview.settings.target]
server_type = "cx23"
location = "nbg1"
ssh_keys = ["my-hetzner-key"]
allowed_ssh_cidrs = ["198.51.100.42/32"]
token = { secret = "hetzner-token" }

[profiles.preview.settings.exposure]
mode = "public"
tls = "acme-http-01"

[profiles.preview.settings.dns]
domain = "sslip.io"
encoding = "hex-ipv4"

[profiles.preview.app_env.api]
RUST_LOG = "info"
DATABASE_URL = { secret = "preview-database-url" }
```

Plugin-specific settings are opaque to the core except for structural and
plugin validation. Each manifest exposes a versioned JSON Schema and prompt
hints. The current `init` flow has built-in questions for the five bundled
plugins; it does not yet render arbitrary third-party schemas interactively.
The core validates capability assignments; `init` and the Compose plugin
verify that every app maps to an existing Compose service and internal port.

### 4.3 Compose and environment values

Lightrail must preserve standard Compose interpolation behavior from:

- the invoking shell;
- `.env`;
- Compose `env_file` entries; and
- `${VARIABLE}` defaults.

Explicit profile/app values in `lightrail.toml` override Compose values.
Resolution occurs locally before provisioning; missing required variables must
fail before remote resources are created.

For SSH/Hetzner, Compose `configs` and `secrets` backed by `file:` are
transferred as deployment material. The native Kubernetes translator currently
rejects those Compose entries; Fly rejects application secret references.
Local bind mounts are rejected because they depend on developer paths and can
copy source unexpectedly. Application source reaches the target only inside
images built from the declared build contexts.

The desired project root must resolve to exactly the Git root granted in the
operation context. Compose files, local build contexts, Dockerfiles, and
file-backed configs/secrets must exist inside that root after symbolic-link
resolution. The SSH/Hetzner runtime accepts only the normalized implicit
`default` network and environment-scoped generated volume names; custom,
external, multiple, aliased, static-address network semantics and custom
volume names/drivers/options fail during validation.

For `up`, core writes the output of `docker compose config --format json` to a
local process-lifetime temporary file. That file preserves Compose's resolved
shell, `.env`, `env_file`, and interpolation values and disappears when the
operation ends. The Compose plugin removes service environments and
`env_file` entries from the persistent remote base document, writes the
resolved environment as a mode-`0600` temporary override, includes it only for
`docker compose up`, and deletes it immediately afterward. Generated remote
Compose documents and transferred config/secret files are also mode `0600`;
the rediscovery manifest omits app environment values.

Named volumes begin empty for a new environment and are scoped to that
environment. Kubernetes persistent volume claims and Fly volumes follow the
same lifecycle: repeated `up` preserves them and `down` deletes them.

## 5. Initialization

`lightrail init` is interactive by default and must:

1. locate the Git project root and Compose input;
2. create the first profile using `--profile` or the `preview` default, then
   ask for the target and required target settings;
3. detect Compose services, build contexts, and candidate ports;
4. ask which services are public apps and which internal port each uses;
5. create an immutable project ID and default profile;
6. select the bundled Compose plugin plus the SSH, Hetzner, Kubernetes, or Fly
   provider plugin;
7. write `lightrail.toml` and `lightrail.lock`;
8. ensure generated `.lightrail/` state is ignored; and
9. validate the resulting configuration without provisioning.

Initialization must also support a fully non-interactive path for automation.
The file-driven form accepts TOML or JSON:

```console
lightrail init --from answers.toml
```

`--from` implies non-interactive mode. The explicit `--non-interactive` flag
requires `--from` because provider-specific settings need a complete input
channel. `--profile <name>` chooses the first profile name, defaulting to
`preview`. Initialization refuses to overwrite `lightrail.toml`; `--force`
allows a validated replacement while preserving the immutable project ID.

A generic SSH answers file requires `settings.target.host`. If `host` is not
itself a publicly routable IPv4, `settings.target.public_ipv4` is also
required:

```toml
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

Hetzner initialization requires at least one existing SSH key name or ID and
at least one explicit, non-world-open operator CIDR:

```toml
project_slug = "myproject"
compose = ["compose.yaml"]
target = "hetzner"
isolation = "machine"
dns_domain = "nip.io"

[[apps]]
name = "frontend"
service = "web"
port = 3000

[settings.target]
server_type = "cx23"
location = "nbg1"
ssh_keys = ["my-hetzner-key"]
allowed_ssh_cidrs = ["198.51.100.42/32"] # replace with your operator CIDR
```

The generated Hetzner profile references `hetzner-token`; set the value before
inspection or deployment:

```console
lightrail secret set hetzner-token
```

Kubernetes initialization requires an existing kube context, an OCI registry
host and repository prefix, an existing NGINX or Traefik ingress class, and
the exact LoadBalancer Service backing that class:

```toml
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
kubeconfig = "/home/me/.kube/config" # optional absolute path
registry = "ghcr.io"
repository = "my-team/previews"
ingress_class = "nginx"
ingress_service_namespace = "ingress-nginx"
ingress_service_name = "ingress-nginx-controller"
namespace_prefix = "lr"
control_namespace = "lightrail-system"
dns_domain = "sslip.io"
cluster_issuer = "letsencrypt"
# image_pull_secret = "registry-pull"
replicas = 1
ttl_hours = 72
command_timeout_seconds = 300
readiness_timeout_seconds = 300
```

The selected cluster, context, control namespace and RBAC, ingress class,
exact ingress-controller LoadBalancer Service, configured cert-manager
`ClusterIssuer`, and registry already exist. The issuer must report Ready and
contain an HTTP-01 solver. A configured image-pull Secret must be made
available in each environment namespace by existing admission/setup policy;
Lightrail does not copy local registry credentials. Lightrail neither
provisions those shared components nor changes an existing ingress controller.
With `platforms = []`, Lightrail discovers Linux architectures from Ready,
schedulable nodes. An explicit list must be a subset of that observed set and
constrains both image builds and Pods: one architecture uses a node selector,
while multiple architectures use required node affinity. The local Docker
client must be authorized to push, and cluster pull authorization is a
separate prerequisite.

Kubernetes initialization supplies `cluster_issuer = "letsencrypt"` by
default, but the resulting plugin setting is required, non-empty, and must
name an existing Ready cert-manager `ClusterIssuer` with an HTTP-01 solver.
Other defaults are
`namespace_prefix = "lr"`, `control_namespace = "lightrail-system"`,
`dns_domain = "sslip.io"`, `platforms = []`, `replicas = 1`,
`ttl_hours = 72`, `traefik_http_entrypoint = "web"`,
`traefik_https_entrypoint = "websecure"`, and both command/readiness timeouts
at 300 seconds. The two Traefik entrypoint names must be distinct DNS labels.
Replicas are limited to 1–100, TTL to 1–8760 hours, and each timeout to
1–3600 seconds. `kubeconfig`, when set, must be an absolute normalized path;
`image_pull_secret`, when set, names an existing Secret available under the
environment namespace's cluster policy. `registry` is a non-loopback host
without a URL scheme or repository path; `repository` is configured
separately. `namespace_prefix` is a DNS label no longer than 32 characters.
`ingress_service_namespace` is a DNS subdomain and `ingress_service_name` is
a DNS label; both are required and identify the one exact existing
LoadBalancer Service whose status supplies the public ingress address.

The Kubernetes source translator rejects every non-empty service field it
does not explicitly translate or validate, including `network_mode`,
privileged containers, local bind mounts, and Compose `configs`/`secrets`
entries. Only the normalized implicit Compose `default` network is accepted;
custom, external, multiple, aliased, statically addressed, driver-configured,
or otherwise optioned networks fail closed. Named volumes must use ordinary
environment-owned generated declarations; external volumes, custom names,
drivers, and driver options are rejected, as are non-empty top-level Compose
config or secret declarations. Every service needs `build:` or `image:`. The
operation context's granted Git root is the only build-source authority:
contexts and explicit Dockerfiles must resolve inside it after symbolic-link
resolution. Clean revision identity converts those paths to project-relative
form and removes only validated directory-derived Compose project, implicit
network, and named-volume names. Because Git cannot prove that ignored files
are absent from a Docker build context, every local-build revision also
includes the operation ID; Buildx still reuses content-addressed layers.
Resolved service environment values are replaced by a key-only shape before
revision hashing and never produce a plaintext-derived provider label. A
named-volume service is stateful by default; `x-lightrail: { kind: stateful }`
makes that intent explicit and `x-lightrail: { kind: job }` selects an explicit
Job. Every non-Job service receives private cluster DNS. When no service port
exists, the translator creates a selector-backed headless Service and does not
guess a port.
Completed Jobs are retained until environment teardown and receive no Job TTL.
An unchanged image-only Job is idempotent across repeated `up`; an existing
local-build Job requires `down` then `up` on every later operation because its
conservative operation-scoped image revision changes the immutable Job spec.
Long-running workloads that use generated environment Secrets receive one
non-secret, operation-derived Pod-template revision per `up`; this rolls
changed environment values into Pods without hashing or retaining secret
plaintext in metadata. NGINX routes get explicit SSL-redirect annotations.
Traefik requires a current or legacy
Middleware CRD (`traefik.io/v1alpha1` or
`traefik.containo.us/v1alpha1`) and receives an environment-owned,
namespace-qualified RedirectScheme Middleware. Any other IngressClass
controller fails validation; there is no generic fallthrough that could omit
the redirect contract. The configured HTTP and HTTPS entrypoint names are used
for the redirect-only and TLS Ingresses respectively; Lightrail never edits
the shared Traefik static configuration.

Kubernetes `up` never uses a destructive replacement to force desired
topology. Removing an owned runtime or exposure resource, adding a runtime
resource to an environment with an observed prior revision, or changing a
present immutable Job fails with explicit `down` then `up` remediation.
Changes to existing Deployments and StatefulSets are explicitly marked
non-reversible because retaining a complete live manifest could retain
injected secret-bearing fields. If a later phase fails, that runtime update is
reported as rollback-incomplete. Initial namespace cleanup and exact
prior-state compensation for Exposure resources and expiry metadata remain
supported. Namespace deletion during `down` or `prune` advertises an explicit
unsupported inverse because deleted workloads, Secrets, PVC objects, and
application data cannot be reconstructed exactly.

Fly initialization uses provider-native environment isolation and creates a
profile with these defaults:

```toml
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
# region = "iad"
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
token = { secret = "fly-token" }
```

Set `fly-token` through the ordinary secret flow before provider inspection or
deployment. Fly uses its native `fly.dev` hostname and does not accept the
`--domain`/`dns_domain` choice. For both environment-isolated providers,
`ttl_hours` defaults to 72 and is refreshed by `up`; expiry is acted on only
by an explicit `lightrail prune`.

Fly creates one deterministic App and exactly one Machine per resolved Compose
service. Every App in the environment joins the same deterministic custom 6PN
membership boundary; Lightrail does not manage that name as a separate network
resource. Only services selected as public apps receive a shared IPv4 and Fly
Proxy routing. A service may have at most one named volume, sized by
`volume_size_gb` (default 3) when it is first created; existing volumes are not
resized. An explicit `region` is required when any named volume is used. Bind
and external volumes are rejected. The current Fly runtime also rejects host
networking, privileged services, `env_file`, Compose `configs`/`secrets`,
unsupported service/deploy fields, and application secret references until a
safe provider-native secret mutation path is implemented. Every service
requires `build:` or `image:`. Compose `command` and `entrypoint`, when
present, must use list form. A Compose `healthcheck` is accepted as source
metadata and remains revision input, but is not translated to a Fly Machine
check. The Lightrail app's `health_path`, `health_status`,
`health_interval_seconds`, and `health_timeout_seconds` are authoritative for
generated Machine checks and final readiness. A configured `health_status`
must be a 2xx value; without one, final endpoint readiness still accepts any
status below 500. Final public readiness also requires the provider-native
HTTPS endpoint and exact HTTP-to-HTTPS redirect. Private services receive no
public Fly service or check from this contract. `auto_stop` and autostart are
Fly Proxy service settings for public services. A private service has no Proxy
wake trigger, so its always-restart Machine remains running and must be counted
in preview cost. An existing environment's exact Compose service/App set is a
continuity boundary: adding or removing a service fails closed and requires an
explicit `down` followed by `up`. Changing named-volume topology or Machine
region, changing the requested `volume_size_gb`, or making a previously public
service private also requires `down` then `up`. In-place revisions of the
existing service set retain their deterministic Apps, but the current plugin
does not implement an exact previous-revision inverse for an existing Machine
update. A failure after such an update is reported as rollback-incomplete.

Fly fixes `registry = "registry.fly.io"` and supports
`platform = "linux/amd64"` or `platform = "linux/arm64"`. Defaults are
`organization = "personal"`, provider-selected region, `app_prefix = "lr"`,
shared CPU kind, one CPU, 256 MiB, `auto_stop = true`, `ttl_hours = 72`,
`lock_ttl_seconds = 3600`, `volume_size_gb = 3`,
`command_timeout_seconds = 300`, and `readiness_timeout_seconds = 300`. Memory
must be at least 256 MiB in 256 MiB increments. Command and readiness timeouts
are each limited to 10–3000 seconds. Lock TTL is limited to 60–86400 seconds
and must exceed the larger timeout by more than 180 seconds; the remaining
numeric capacities must be positive. Organization is a provider slug up to
128 characters; region and `app_prefix` are provider-safe slugs up to 16
characters.

A non-interactive run fails rather than prompting when target or app input is
ambiguous or required target settings are absent.

Additional profiles use:

```console
lightrail profile add <name>
```

The current command clones a template profile: the profile selected by the
global `--profile` option, or the project default when no profile is selected.
Edit the committed clone to change its target or app policy.

## 6. Hostnames, DNS, and TLS

### 6.1 Endpoint layout

SSH and Hetzner public app hostnames are:

```text
<branch>.<app>.<profile>.<project>.<8-hex-ip>.<dns-domain>
```

Only `sslip.io` and `nip.io` are valid IP-DNS domains. Branch is always the
first label and app is always the second for this hostname form. It requires a
public IPv4 address; IPv6-only targets are unsupported.

For IPv4 `203.0.113.10`, encode each octet as two lowercase hexadecimal
characters, preserving zeroes:

```text
203.0.113.10 -> cb00710a
```

For a branch already named `feature-login`, the resulting app URLs are:

```text
https://feature-login.frontend.preview.myproject.cb00710a.sslip.io
https://feature-login.api.preview.myproject.cb00710a.sslip.io
```

Kubernetes uses the configured IngressClass and reads the public address from
the exact configured LoadBalancer Service backing it. The generic plugin uses
a public ingress IPv4 with the same branch-first/app-second hexadecimal
`sslip.io` or `nip.io` form selected by the profile. A load-balancer status
hostname is not itself proof that arbitrary child names are delegated to the
cluster, so a hostname-only Service status fails with remediation instead of
synthesizing an invalid URL. The plugin must not guess among ingress classes
or Services, or modify an existing NGINX, Traefik, or other controller.

Fly creates one App per Compose service. A selected public service receives
the provider-native HTTPS endpoint
`https://<app-prefix>-p<project-marker>-<branch>-<app>-<stable-suffix>.fly.dev`,
subject to Fly name-length normalization. The project marker separates
immutable projects within an organization, the readable identity keeps branch
before app, and the suffix prevents resource collisions. `lightrail urls`
remains authoritative and callers must not synthesize the normalized URL.

### 6.2 Label normalization

For the SSH/Hetzner/Kubernetes IP-DNS form, every branch, app, profile, and
project label must:

1. be lowercased;
2. replace non-DNS-label characters with `-`;
3. collapse repeated `-`;
4. trim leading and trailing `-`;
5. remain at most 63 characters; and
6. keep the complete hostname within DNS length limits.

If normalization changes the original value, if truncation is necessary, or
if a collision is otherwise detected, append `-` plus the first eight
lowercase hexadecimal characters of the SHA-256 hash of the original value.
Truncate the readable prefix as needed so the suffix and full label remain
within limits. Empty normalized labels are invalid.

Fly normalizes branch and app/service fragments inside one provider App name,
not as separate DNS labels. It lowercases them, replaces unsafe runs with
hyphens, trims and truncates them to the available name budget, and relies on
the immutable-project marker plus stable resource suffix for collision
resistance. Callers must use the provider name returned by `lightrail urls`.

Uncommitted changes do not alter a hostname. Detached HEAD uses the
`sha-<12-character-commit>` label described earlier.

### 6.3 Public HTTPS contract

There is no localhost application URL.

- SSH and Hetzner route every public app through Traefik at its final
  hostname.
- SSH targets must reject literal loopback addresses and any hostname whose
  bounded system resolution includes loopback or IPv4-mapped loopback.
- ACME HTTP-01 obtains a certificate for each SSH/Hetzner hostname.
- Port 80 must remain reachable for the HTTP-01 challenge and redirect ordinary
  HTTP traffic to HTTPS.
- Port 443 serves the application with the issued certificate.
- Lightrail must verify the final HTTPS route as part of readiness.
- Wildcard certificates and custom DNS challenges are outside the MVP.
- Kubernetes requires the selected existing ingress/TLS policy to produce a
  trusted HTTPS route. The required named cert-manager `ClusterIssuer` must
  already exist, report Ready, and contain an HTTP-01 solver.
- Kubernetes readiness also requires same-host plain HTTP to redirect to the
  final HTTPS route.
- Fly delegates public TLS and routing to Fly Proxy.

HTTP-01 is an HTTP reachability check, not merely a DNS lookup: the hostname
must resolve to the target and the challenge token must be reachable on port
80. Implementation should follow the official
[Let's Encrypt HTTP-01 description](https://letsencrypt.org/docs/challenge-types/)
and the documented hexadecimal-IP forms of
[sslip.io](https://sslip.io/) and [nip.io](https://nip.io/).

## 7. Build and transport

The developer machine performs application builds; the remote target performs
runtime deployment.

For every Compose service containing `build:`:

1. Discover or validate the target platform (`linux/amd64` or
   `linux/arm64`).
2. Build locally with Docker Buildx for that platform.
3. Enable normal Buildx cache reuse.
4. Tag the output deterministically from environment, service, and revision.
5. For SSH and Hetzner, compare local and remote Docker image IDs, compress
   images whose remote ID differs, and load them into the remote Docker
   engine.
6. For Kubernetes and Fly, push deterministic OCI references to the
   configured provider-reachable registry and deploy those references.

Every `up` requests a Buildx build of build-backed services. Buildx cache and
the target-specific image comparison or registry behavior make unchanged
builds inexpensive. Kubernetes registry authentication is an explicit local
prerequisite and cluster pull authorization is separate from the developer's
push authorization. Fly uses `fly-token` in an isolated temporary Docker
configuration for `registry.fly.io` pushes and resolves locally built tags to
immutable digests before Machine deployment.

Images referenced only by `image:` are pulled by the target runtime. The
current deployment keeps the configured reference rather than rewriting it to
a digest. Strict digest pinning of external images is therefore not yet
implemented.

OCI images pushed for Kubernetes and Fly are deliberately outside the
environment destruction aggregate. `down` retains them as registry build
cache; repository retention and garbage collection remain registry policy.

Lightrail transfers only:

- missing built images;
- normalized/generated Compose material;
- allowed Compose configs and secrets; and
- resolved runtime environment material.

The transfer list applies to the SSH/Hetzner path. Kubernetes and Fly receive
only the pushed OCI artifacts and provider-native desired resources. No target
may receive the source tree as loose files or a copy of persistent
volume/database data.

## 8. Targets and isolation

Profiles set:

```toml
isolation = "project" # or "environment" or "machine"
```

### 8.1 Project isolation

Project isolation is the default for generic SSH:

- environments share a public host;
- each environment has a separate Compose project name;
- networks, named volumes, containers, generated files, and routes are
  environment-scoped;
- one shared Traefik instance serves the host;
- each environment gets a distinct external ingress network named from the
  configured prefix plus its deterministic environment ID;
- Traefik joins each environment ingress network only to reach that
  environment's public apps;
- application environments must not gain connectivity to one another merely
  because Traefik serves both.

`down` removes only the selected environment. It must not remove shared
Traefik or another branch's resources.

### 8.2 Machine isolation

Machine isolation is the default for Hetzner:

- one managed VM belongs to one environment;
- the VM has its own Docker Engine and Traefik;
- `down` deletes the VM and every attached resource managed for the
  environment.

Target plugins may reject an isolation mode they cannot safely provide.

### 8.3 Environment isolation

Environment isolation is the required mode for Kubernetes and Fly:

- one deterministic environment aggregate belongs to one project, profile,
  and raw branch;
- Kubernetes places that aggregate in one environment-owned namespace,
  including workloads, Services, Ingresses, and persistent volume claims;
- Kubernetes claims a new namespace with an atomic create and records the
  configured control namespace as part of its ownership authority;
- Fly represents the aggregate with exactly owned Apps, Machines, and volumes;
  App-attached routing/address state is included only after the same immutable
  Machine ownership continuity is proven;
- repeated `up` reconciles that aggregate while preserving its persistent
  volumes;
- ordinary `down` deletes only that environment's aggregate and volumes; and
- `down --all` discovers and deletes all aggregates for the immutable project
  visible through the selected context/account and credentials.

The existing Kubernetes cluster, nodes, control namespace, ingress controller,
certificate issuer, registry, and registry images are shared prerequisites
and remain after environment destruction. Fly registry images are likewise
retained as build cache. For the safe initial contract, every mutation on an
Environment-isolated profile takes one project lock. Resource isolation
remains per environment, but different branches do not mutate the same
Kubernetes project/Fly project concurrently.

## 9. Bootstrap

Generic SSH defaults to automatic, idempotent bootstrap:

- detect compatible Docker Engine, Compose, and required host capabilities;
- reuse a compatible installation;
- install missing components only on explicitly supported Linux
  distributions, using root or passwordless `sudo`;
- create or verify the configured remote root and remote locking
  prerequisites;
- inspect listeners and known firewall state for ports 80 and 443, SSH access,
  architecture, and required Docker features;
- never replace or alter an incompatible installation blindly;
- stop with exact remediation instructions when automatic bootstrap is unsafe.

A profile can choose verification-only mode:

```toml
[profiles.preview.settings.target]
bootstrap = "verify"
```

Hetzner machines receive the same Docker baseline through cloud-init.
Traefik and the per-environment ingress networks are reconciled by the
Compose plugin after target bootstrap. Re-running either phase must converge
safely.

Kubernetes has no bootstrap or cluster-setup phase. Preflight uses the
explicit context, reads the existing control namespace and IngressClass,
discovers architectures from Ready, schedulable Linux nodes, and observes the
exact configured ingress-controller LoadBalancer Service. Explicit
`platforms` must be a subset of those observed architectures. It rejects a
literal or resolved loopback Kubernetes API host before mutation. Other RBAC,
registry pull, certificate, admission, storage, and image-pull Secret
prerequisites are checked by the operator or at their first exact use.
Lightrail does not create clusters, nodes, shared namespaces, RBAC, ingress
controllers, certificate issuers, registries, or pull credentials.

Fly is agentless. Preflight validates the explicit organization, region when
set, provider credential, build platform, and provider access; it never
installs a Lightrail daemon or logs into a remote machine.

## 10. Network boundary

Lightrail never edits the user's Compose files. SSH/Hetzner generate a private
deployment override. Kubernetes/Fly translate the resolved Compose intent into
provider-native resources.

For SSH and Hetzner, the generated deployment must:

- remove host-published ports by default;
- expose selected HTTP apps only through Traefik using internal service ports;
- create a private, environment-scoped application network;
- create a separate environment-scoped ingress network and connect only
  Traefik and selected public app services to it;
- leave unselected services inaccessible from the public internet;
- reject `network_mode: host`;
- reject local bind mounts;
- reject unsupported raw TCP/UDP public exposure.

For managed Hetzner infrastructure, the managed firewall exposes:

- TCP 80 to the internet;
- TCP 443 to the internet; and
- SSH only from configured operator CIDRs.

Generic SSH validates required connectivity and reports firewall remediation,
but must not rewrite an unknown host firewall.

For Kubernetes:

- each environment has its own namespace and default-private Services;
- every non-Job service has private cluster DNS, including a selector-backed
  headless Service when the Compose service declares no port;
- only selected public apps receive Ingress routes through the exact
  configured existing NGINX or Traefik IngressClass;
- no app container port is exposed through a host port or NodePort by
  default; and
- Lightrail never guesses between or rewrites NGINX, Traefik, or another
  ingress controller.

For Fly, selected public apps use Fly Proxy and provider-managed TLS. Services
not selected as public remain private within the environment's provider-native
network boundary. Service-to-service discovery uses the deterministic Fly App
name as `<owned-app>.internal`; original Compose service aliases are not
preserved. Tunnels and private-only developer access are not implemented.

## 11. Deployment and readiness

`lightrail up` must run these conceptual phases:

1. resolve project, branch, profile, and deterministic environment identity;
2. validate Compose, plugin compatibility, tools, configuration, and secrets;
3. preflight-inspect the target so the plugin can locate its lock authority;
4. acquire the environment mutation lock;
5. re-inspect provider/runtime state and produce the authoritative plan while
   holding that lock;
6. display the locked plan for human output, while JSON/plain automation uses
   the matching `--dry-run` as its single-document plan review;
7. build and resolve images;
8. provision/bootstrap the target if needed;
9. transfer images and generated material or push deterministic OCI
   references;
10. apply the Compose or provider-native runtime and routing configuration;
11. wait for service and HTTPS readiness;
12. record the healthy revision and print every app URL.

`up --dry-run` remains read-only: it performs the fullest inspection and
planning available without acquiring a lock, then exits. A real `up` never
applies that pre-lock plan; it re-prepares everything under the lock.
Real JSON/plain mutations reserve stdout for one final result rather than
emitting two incompatible documents; their locked plan still participates in
continuity checks and the operation journal.
Destruction is also re-inspected and re-planned after locking. If its action
contract changed while the user was reviewing or confirming it, `down` aborts
and asks the user to rerun it rather than applying an unconfirmed plan.
Plan continuity covers a canonical digest of the complete serialized
`PlanResult`, including actions, dependencies, rollback metadata, and plugin
metadata; matching only a plan ID or action summary is insufficient.

Readiness succeeds only when:

- on SSH/Hetzner, every Compose service with a health check reports healthy
  and every service without one remains running through a short stability
  window;
- on Kubernetes, every applied long-running workload completes its
  provider-native rollout and every Job completes; these waits run
  concurrently under one runtime readiness deadline;
- on Fly, every required Machine reaches the expected provider/runtime state;
- every public app responds through its final HTTPS hostname with a valid
  certificate;
- the default route probe receives a status below 500, allowing valid API
  responses such as 401, 403, or 404;
- an app with `health_path` and `health_status` satisfies that stricter
  requirement.

Runtime wait and HTTPS probe phases are independently bounded. HTTPS checks
execute concurrently. Profiles/apps may change the path, expected status,
interval, stability window, and supported timeouts. SSH/Hetzner Compose wait
and HTTPS checks default to five minutes; Kubernetes
`readiness_timeout_seconds` defaults to 300. A configured phase timeout is not
a single wall-clock timeout for the entire `up` command.

Core derives the surrounding protocol deadline from exact work units. Each
locked-plan action or exact destroy selection receives one command phase plus
one readiness phase, followed by a five-minute coordination margin; configured
phase contributions are capped at 60 minutes and the complete request at 24
hours. Provider inspection uses that explicit maximum because its result
defines the previously unknown remote work count. Plugins must not hide
additional sequential phase multipliers inside one planned action.

## 12. Repeated `up` and rollback

Repeated `up` reconciles the current environment:

- routes and hostnames stay stable;
- SSH/Hetzner Compose applies the new revision in place and removes orphans;
- Kubernetes and Fly reconcile deterministic provider-native resources;
- environment-scoped named volumes, persistent volume claims, and Fly volumes
  are preserved; and
- SSH/Hetzner retain the previous generated deployment documents; native
  providers use their locked pre-apply observations to define only the
  rollback actions they explicitly support.

Automatic rollback is the default.

- The journal identifies every planned/completed action by plugin, capability,
  exact plan ID, and action ID. `down` and `prune` journal the exact locked
  plans and mark completion from returned destroy action journals; they assume
  all planned actions completed only when destruction reports no remaining
  state.
- A failed initial deployment removes resources newly created by that
  operation. Core passes the plugin's post-apply rediscovery state to
  whole-capability cleanup when apply returned one, so cleanup is scoped to
  what that attempt actually created; if apply failed before returning state,
  the plugin must use the locked context and exact deterministic resource
  identities to find only that attempt's resources.
- Fly records provisional App, Machine, and volume identities during initial
  creation so partial target cleanup stays exact. If exposure allocated a
  shared IPv4 before a later failure, rollback releases that exact App/address
  pair.
- A failed update restores the previous generated Compose documents and
  reapplies them where possible on SSH/Hetzner. Provider-native plugins
  compensate their exact applied actions where supported.
- Provider-native update restoration is not a blanket guarantee: core invokes
  only rollback actions explicitly advertised in the locked plan/journal. An
  unsupported or failed compensation is reported for explicit recovery.
  A provider mutation must advertise either a supported exact inverse or an
  unsupported contract with a safe reason; a potentially executed existing
  Target or Runtime action with no contract is itself reported as incomplete
  rollback.
- Previously loaded built images remain in the remote Docker cache. OCI images
  pushed for Kubernetes or Fly remain in the registry cache even when apply
  fails or an environment is rolled back.
- Transient failures use bounded retries with backoff; permanent validation or
  authorization failures fail immediately.
- `--keep-failed` preserves failed resources for debugging and records the
  failure in the local operation journal.
- If cleanup itself is incomplete, the command records and reports the
  remaining failure.

Followed logs handle Ctrl+C. During an in-flight `up`, Ctrl+C sends semantic
`plugin.cancel`, waits for the active plugin to reach a safe stopping point,
and then follows the normal failure and rollback path unless `--keep-failed`
was selected. `down` uses the same safe-point cancellation mechanism and stops
before beginning another destroy step. If apply returns a successful result
concurrently with cancellation, core journals its exact returned post-state
before entering rollback and never commits the cancelled revision as a
success.

Rollback cannot reverse:

- database migrations;
- data written to named volumes;
- side effects against external systems;
- historical application environment or secret values. The temporary
  override is deliberately not retained; rollback can re-render only the
  currently available values for the attempted deployment's references;
- movement of a mutable external image tag;
- an infrastructure failure that makes the prior target unavailable.

Brief container recreation downtime is acceptable in the MVP.

## 13. Concurrency

Only one mutating operation (`up`, `down`, or `prune`) may own an overlapping
lock scope at a time.

- Target plugins must provide an operation-lock capability. The core must
  refuse an unsafe mutation when no authoritative lock is available.
- Before every plugin apply or destroy call, core must reacquire the same
  scope and owner and require the exact original opaque token. A stale,
  missing, or changed token aborts before that mutation.
- Lock requests carry a scope plus stable `scope_id`: `environment` protects
  one branch/profile environment, `project` protects all environments for an
  immutable project ID, and `target` protects shared target-wide resources.
- Generic SSH uses target scope and a host-wide POSIX `mkdir` lock at
  `/tmp/lightrail-host.operation.lock`. The SSH session holds stdin open and
  removes the directory on release, so the host does not need `flock`.
- Hetzner uses environment scope for one machine and project scope for
  `--all`. It snapshots the exact labeled resource set and holds remote
  `flock` processes on every reachable machine selected by the scope. Initial
  provisioning upgrades its session reservation to the new machine's remote
  lock after bootstrap; a failed upgrade preserves the machine for explicit
  recovery. Project operations acquire machine locks in deterministic
  provider-ID order without serializing unrelated environment operations.
- Kubernetes serializes every mutation for one immutable project through a
  project-scoped `coordination.k8s.io/v1` Lease in the configured existing
  control namespace. Lease acquisition and expiry use optimistic
  `resourceVersion` continuity; an active owner heartbeats until release or
  process loss, and same-owner reacquisition returns the identical live token.
- Every owned Kubernetes namespace records that control namespace. Changing it
  while the environment exists fails before mutation, preventing a different
  Lease from silently replacing the original authority. Initial namespace
  ownership uses an atomic create; `AlreadyExists` and lost-response recovery
  continue only after exact ownership, control-namespace, and planned
  spec-hash reinspection, never by applying over competing ownership.
- Fly intentionally serializes all project mutations, including
  current-environment `up`/`down`, behind one deterministic provider-visible
  lock App and stopped sentinel Machine lease. The shared lock App is retained
  during environment teardown. `lock_ttl_seconds`, default 3600, bounds stale
  lease recovery; a process-local mutex alone is never authoritative.
- A provisioning VM cannot normally be destroyed until its operation
  completes or fails.
- Mutating commands wait for up to 30 seconds by default. `--lock-timeout`
  changes that wait.
- `status`, `urls`, and `logs` are read-only and do not require the mutation
  lock.
- If a machine-isolated remote lock authority is unavailable, bypassing it
  for provider-side destruction requires `down --force` and explicit
  confirmation. Force never bypasses a busy lock and is not available for the
  shared generic SSH lock or environment-isolated Kubernetes/Fly targets.
- Connection-scoped locks release with their owning process/SSH session.
  Lease-backed locks stop heartbeating and become recoverable only under their
  declared expiry/continuity rules.

## 14. Destruction

`lightrail down` targets the current project, branch, and selected profile by
default.

Before changing anything it must:

1. rediscover owned resources;
2. prepare a destruction plan and display it for human output or every
   `--dry-run`; JSON/plain real runs reserve stdout for the final result;
3. require interactive confirmation, unless `--yes` was provided; and
4. support `--dry-run` to stop after the plan.

For project isolation it removes the environment's containers, networks,
volumes, routes, and generated environment directory. Shared Traefik and
resources owned by other environments remain. It also removes images in the
`lightrail/*` namespace that carry the exact managed/project/environment
labels; unrelated and external images remain.

For machine isolation it deletes the managed VM and all attached
Lightrail-managed resources.

For environment isolation, Kubernetes deletes only the exact owned namespace
and therefore its owned workloads, Services, Ingresses, Secrets, jobs, and
persistent volume claims. Fly deletes only the exact owned environment's Apps,
Machines, and volumes. A normal App requires exact Machine ownership metadata;
a zero-Machine interrupted-create orphan is eligible only when its stable
project marker, deterministic project-network prefix, and captured App/network
and volume IDs all remain continuous. An App name alone never authorizes
deletion. Shared IPv4 and routing state are App-attached; the deterministic
custom 6PN name is not a separately deleted resource. Neither path deletes
registry images; Fly also retains the project lock App.

`down --all` targets every labeled project environment discoverable through
the selected profile's configured target and credentials, and requires
stronger explicit confirmation. On a shared host it deletes exactly owned
containers, volumes, networks, generated environment directories, and labeled
`lightrail/*` images while retaining shared Traefik. On Hetzner it discovers
and deletes every visible project-labeled server and firewall, including
branches other than the branch in the current worktree. Profiles pointing at a
different host, provider account, or credential boundary must be cleaned
separately. Destruction is idempotent: rerunning `down` continues interrupted
resource cleanup. Deletion is not rollback-capable.

`down --force` is a recovery override only for an unavailable remote lock
authority in machine isolation. It does not bypass a lock reported as busy,
does not imply `--yes`, and does not weaken ownership selectors. It permits
provider-side deletion of labeled Hetzner servers and firewalls even when
remote Compose cleanup cannot run. With project isolation the shared SSH host
is always retained; if that host is unreachable, remote environment resources
cannot be removed and require a later retry. Environment-isolated Kubernetes
and Fly profiles do not support `--force`.

### 14.1 Expiry pruning

`lightrail prune` is available only for environment-isolated provider plugins
that advertise `dev.lightrail.selected-destroy.v1` and aggregate target,
runtime, exposure, and DNS destruction in that one plugin.

The command:

1. performs project-wide inspection through the selected profile context or
   account;
2. accepts only environment-contract version 1 observations with an exact
   immutable project ID, unique environment ID, and provider-visible expiry;
3. selects only entries whose `expires_at_unix` is at or before the command's
   captured current time;
4. prepares an exact destructive plan, displaying it for human output or
   every `--dry-run`;
5. stops after the plan for `--dry-run`, otherwise requires confirmation or
   `--yes`;
6. takes the project mutation lock, reinspects against the same captured time,
   and aborts if either the candidate set or the canonical digest of the full
   serialized plan changed; and
7. sends the exact selected IDs to the provider and requires no remaining
   resources.

The selected-destroy operation uses selection schema 1 with reason `expired`.
It must never fall back to unselected `down --all`. Registry images, the
Kubernetes cluster/control namespace/ingress components, and the Fly lock App
remain. Cleanup is explicit; Lightrail does not run a background expiry
controller.

## 15. Secrets

Committed configuration contains references, never secret values:

```toml
token = { secret = "hetzner-token" }
```

Resolution precedence is:

1. CI/environment override;
2. OS keyring;
3. interactive prompt when interaction is allowed.

The environment override is `LIGHTRAIL_SECRET_` plus the uppercased logical
secret name with each non-alphanumeric character replaced by `_`. For example,
`hetzner-token` resolves from `LIGHTRAIL_SECRET_HETZNER_TOKEN`. CI systems
should populate that variable from their protected secret store rather than
putting values in arguments or committed files.

Plugins declare required secret names in their manifests. The core resolves
only those names and sends their values through the plugin's JSON-RPC stdin
channel. Secret values must never be:

- command-line arguments;
- written to `lightrail.toml`, `lightrail.lock`, local state, plans, or
  journals;
- printed in logs, progress output, or structured errors; or
- supplied to unrelated plugins.

Protocol 1.0.0 also permits a manifest declaration named `"*"`. It means
“accept explicit secret references for this capability,” not “read every
stored secret.” When a plugin declares the wildcard, core scans only the
selected capability settings and, only for a runtime `up`, the desired app
environment. It resolves and sends only names found in explicit
`{ secret = "name" }` references. `dev.lightrail.compose` uses an optional
wildcard for application environment secrets during deployment. Read-only
inspection, URLs, logs, and a standalone `down` do not prompt for or transmit
application secrets. A runtime rollback within `up` may reuse that operation's
already resolved context. Explicit provider credentials are still resolved
for operations whose plugin declares them as required.

Without the wildcard, every referenced name must be listed explicitly by the
plugin or core rejects the operation. `dev.lightrail.hetzner` declares only
the required `hetzner-token`; `dev.lightrail.ssh` declares no secrets and uses
the local OpenSSH client, optional key path, and SSH agent.

`dev.lightrail.kubernetes` accepts only explicit application secret
references needed by an `up`; it submits their values through `kubectl` stdin
and never puts them in command arguments or generated diagnostic output. It
uses the explicit `kubeconfig` setting when supplied, otherwise the narrowly
forwarded `KUBECONFIG`/ordinary kubeconfig lookup. Local registry push
credentials and the cluster's pull credentials are separate external
prerequisites, not values copied automatically between those boundaries.
Generated Opaque Secrets persist in the Kubernetes API until the environment
namespace is deleted; API RBAC, audit policy, and etcd encryption are cluster
operator responsibilities.

`dev.lightrail.fly` declares the required `fly-token`. Core resolves that
logical secret only for Fly capabilities and supplies it over JSON-RPC stdin;
it is not inherited as an ambient `FLY_API_TOKEN`.

Remote temporary environment files use mode `0600` and are removed after
container creation. Values placed in container environment variables remain
visible through normal privileged Docker inspection; file-mounted secrets
should be preferred when applications support them.

Secret references apply to provider credentials and application configuration.
The CLI provides:

```text
lightrail secret set <name>
lightrail secret list
lightrail secret delete <name>
```

`list` shows names only, never values.

## 16. Agentless discovery and state

Lightrail has no daemon, remote agent, or required central state service.

The authoritative inputs and observations are:

- committed project and plugin configuration;
- deterministic environment identity;
- provider resources labeled with ownership metadata; and
- Docker/Compose, Kubernetes, or Fly resources labeled with ownership and
  revision metadata.

Labels must carry enough information to rediscover at least project ID,
environment ID, profile, branch identity, resource role, managed ownership, and
revision where relevant.

Kubernetes project-wide discovery lists exact project-labeled namespaces and
their owned resources through the selected context. Fly discovery queries
provider resources visible through the selected organization and credential.
Neither may treat `.lightrail/` as ownership authority.

`.lightrail/` is only a cache and operation journal. Losing it must not prevent
another developer or CI runner with the repository and credentials from
running `status`, `urls`, `up`, or `down`.

A remote-state backend may become a plugin later, but cannot be required by
the MVP.

## 17. Plugin model

The Rust core owns only:

- CLI and configuration precedence;
- validated project/environment identity;
- plan orchestration and operation journal;
- cancellation, bounded retry, rollback coordination, and output;
- plugin discovery, pinning, protocol compatibility, and process lifecycle;
- minimal secret resolution and redacted protocol wrappers.

External executable plugins provide capabilities such as:

- `dev.lightrail.compose`: source, Buildx builder, Compose runtime, Traefik
  exposure, and IP-derived DNS;
- `dev.lightrail.ssh`: generic SSH target and remote operation lock;
- `dev.lightrail.hetzner`: Hetzner target and remote operation lock;
- `dev.lightrail.kubernetes`: existing-cluster builder, target, runtime,
  ingress/DNS, readiness, and Lease lock;
- `dev.lightrail.fly`: agentless builder, target, runtime, Fly Proxy/DNS,
  readiness, and provider-backed operation lock;
- unimplemented extension points for future usage, tunnel, k3s, GitHub,
  GitLab, and remote-state plugins.

Bundled plugins must use the same versioned JSON-RPC-over-stdin/stdout contract
as third-party plugins. Rust dynamic libraries are not a plugin ABI.

The five bundled plugins ship with Lightrail and are resolved as sibling
executables. Their manifest ID and package version are verified during
handshake. Bundled resolution uses a canonical absolute sibling path and
fails closed when it is unavailable; it never searches `PATH`. Third-party
plugins are installed only through explicit plugin
commands from a local executable or an explicitly supplied HTTPS URL; `up`
never downloads one automatically.

`lightrail.lock` pins each third-party plugin's:

- ID;
- version;
- protocol version;
- source; and
- SHA-256 checksum.

`plugin sync` installs exactly the pinned third-party set for CI or another
developer. Only `plugin install`, `plugin update`, and `plugin remove` change
pins. Core validates the manifest, checksum, capabilities, and protocol
compatibility before execution, and compares the canonical pinned protocol
version exactly with the executable manifest's emitted version. Bundled plugin
IDs need no lock entry.

Native plugins run with the invoking user's OS permissions and are not
sandboxed. Processes receive a sanitized environment and only their declared
secrets.

See [plugin-protocol.md](plugin-protocol.md) for the implemented wire contract.

## 18. CLI contract

### 18.1 Commands

```text
lightrail init [--from <file>] [--target ssh|hetzner|kubernetes|fly] [--domain sslip.io|nip.io] [--profile <name>] [--force]
lightrail profile add <name> [--from <profile>]|list|show <name>|remove <name>|default <name>
lightrail up [--dry-run] [--keep-failed] [--lock-timeout <time>]
lightrail status [--all]
lightrail urls [--all]
lightrail logs [service] [--follow] [--tail <count>]
lightrail down [--all] [--dry-run] [--yes] [--force] [--lock-timeout <time>]
lightrail prune [--dry-run] [--yes] [--lock-timeout <time>]
lightrail doctor [--target]
lightrail secret set <name> [--stdin]|list|delete <name>
lightrail plugin install <source>|sync|list|inspect <id>|update <id>|remove <id>
lightrail completion <shell>
lightrail version
```

Global options:

```text
-p, --profile <name>            select a profile; name the first one for init
-o, --output human|json|plain   select the output renderer
-v, --verbose                   increase diagnostic verbosity
```

Important command options:

```text
-n, --dry-run          display a plan without mutation (`up`, `down`, `prune`)
--keep-failed          preserve a failed deployment (`up`)
-a, --all              act on project environments visible through the selected profile target
--follow               stream logs
--tail <count>          historical log records, default 100
--yes                  confirm destruction non-interactively (`down`, `prune`)
--force                machine-only unavailable-lock recovery for destruction
--lock-timeout <time>  mutation-lock wait, default 30 seconds
```

Followed logs handle Ctrl+C. For an in-flight `up`, `down`, or `prune`, the
CLI sends semantic operation cancellation, waits for the active plugin's safe
stopping point, and then performs rollback or an orderly stop as applicable.
The protocol client also cancels individually timed-out requests.
Human-readable progress and errors go to stderr; command data and `--output
json` output go to stdout. JSON log output is newline-delimited so followed
logs remain streamable. Any unsuccessful operation exits non-zero.

### 18.2 Command behavior

- `init`: discover Compose and create the project and first profile. Target and
  DNS flags can skip those interactive choices. `--force` is required to
  reconfigure and must preserve the existing immutable project ID. Users must
  destroy live environments before force-reconfiguring profiles or targets.
- `profile add|list|show|remove|default`: manage committed named profiles.
  `add` clones the `--from`, globally selected, or default profile, in that
  order. `default` changes selection when `--profile` is omitted. Removal
  refuses to orphan discovered live environments.
- `up`: plan, build, transfer or push, deploy, verify, then print all app
  URLs.
- `up --dry-run`: perform discovery and validation and print the complete
  obtainable plan without provisioning, building, or mutating.
- `status`: rediscover and summarize the current environment.
- `urls`: print every app and final HTTPS URL for the current environment.
- `status --all` and `urls --all`: aggregate project environments rediscovered
  through the selected profile's configured target and credentials, with
  branch/profile metadata, status, and endpoints. On a shared SSH host Compose
  inspects exact labels and owned manifests. For machine isolation the target
  returns every labeled machine visible to that provider configuration and
  core fans out downstream runtime inspection; an unreachable machine remains
  visible as a degraded endpoint-free summary instead of hiding the rest.
  Environment-isolated providers return the exact owned Kubernetes namespaces
  or Fly aggregates visible through the selected context/account, including
  provider expiry metadata when present.
- `logs [service]`: read logs when the selected runtime implements them.
  SSH/Hetzner Compose supports historical and followed logs. Kubernetes
  supports historical logs but returns `unsupported` for `--follow`; Fly
  currently returns `unsupported` for both historical and followed logs.
  Service is optional when the runtime supports aggregate logs.
- `down`: execute the destruction contract in section 14.
  Declining the pre-mutation confirmation is a successful no-op.
- `prune`: for an environment-isolated Kubernetes/Fly profile, discover and
  plan the exact expired project environments visible through that selected
  provider boundary. It requires a feature-capable aggregate provider plugin,
  explicit confirmation unless `--yes` is set, and a project lock with exact
  reinspection. `--dry-run` is read-only.
- `doctor`: validate the common local Git, Docker client/daemon, Buildx, and
  Compose prerequisites. Target-specific validation adds OpenSSH for
  SSH/Hetzner, `kubectl` and the selected context for Kubernetes, or Fly API
  access for Fly. `doctor --target` invokes target inspection with the
  selected profile and only its required credentials.
- `secret`: manage named secret references through the configured local secret
  store. A missing secret entered during another interactive command is cached
  only for that command and is never persisted implicitly.
- `plugin`: explicitly install, pin, synchronize, inspect, update, list, and
  remove plugin executables.
- `completion`: generate shell completion.
- `version`: print the CLI release version.

## 19. Platform matrix

The initial supported developer platforms are:

- Linux `amd64`;
- Linux `arm64`;
- macOS `amd64`;
- macOS `arm64`; and
- WSL2 treated as Linux.

Native Windows is deferred.

Common deployment prerequisites are Git and Docker Engine or Docker Desktop
with Buildx. SSH/Hetzner additionally require OpenSSH. Kubernetes requires
`kubectl`, an existing explicit context, and an authenticated OCI registry.
Fly requires provider API access through `fly-token`. `doctor` and provider
preflight verify the applicable subset before mutation.

SSH/Hetzner targets are Linux `amd64` or `arm64`. Generic automatic bootstrap
initially supports Ubuntu and Debian families. Hetzner uses a supported Ubuntu
image by default. Kubernetes supports Ready, schedulable Linux `amd64` and
`arm64` nodes; Fly uses the configured platform, initially `linux/amd64`.

SSH/Hetzner detect remote architecture. Kubernetes discovers architectures
from Ready, schedulable nodes unless `platforms` is explicit. An explicit list
must be a subset of the observed set and constrains both Buildx output and Pod
scheduling, using a node selector for one architecture or required node
affinity for several. Fly uses its explicit `platform`. A cross-architecture
build uses Buildx/QEMU. If the local builder cannot provide a required
platform, deployment fails with exact remediation instructions.

## 20. Deferred roadmap

None of the features below is implemented. The plugin and profile model
preserves extension points for:

- authenticated private tunnels with no public inbound application ports;
- k3s cluster provisioning and lifecycle;
- Kubernetes cluster/node provisioning and shared-component setup or upgrade;
- a background/automatic expiry controller;
- GitHub/GitLab pull-request event automation while retaining the current-CWD
  workflow;
- provider-aware usage and cost reporting;
- user-selectable blue/green, canary, or advanced rollout strategies;
- custom DNS plugins outside the MVP;
- remote state backends; and
- native Windows developer support.

Deferred features must not weaken MVP invariants. In particular, future private
mode must not quietly expose public ports, and future CI automation must not
make GitHub a requirement for local current-worktree deployment.
