# Lightrail product specification

Status: implemented MVP contract. The CLI, protocol, and bundled Compose, SSH,
and Hetzner plugins are present and covered by automated tests. See the README
for current live-validation status; this document intentionally keeps the
behavioral contract independent of dated smoke-test results.

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
runs ordinary infrastructure components such as Docker, Compose, and Traefik,
but no Lightrail daemon.

### 1.1 MVP goals

The MVP must:

1. Create reusable, named deployment profiles with `lightrail init`.
2. Treat the current Git worktree and branch as the source revision.
3. Build Compose services locally and deploy them to generic SSH or Hetzner
   targets.
4. Expose several apps in one project at separate, predictable HTTPS
   subdomains.
5. Isolate environments either as separate Compose projects on a shared host
   or as separate machines.
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
- Fly.io, Kubernetes, or k3s targets;
- custom DNS zones or DNS-provider APIs;
- raw public TCP or UDP services;
- blue/green or rolling deployment;
- remote shell execution;
- a usage or cost-reporting command;
- native Windows support;
- a central control plane, hosted service, or remote Lightrail agent;
- automatic third-party plugin downloads during deployment;
- a central plugin marketplace;
- restoration of application data changed by a failed revision.

The architecture must leave clear extension points for these future
capabilities without pretending they are available now.

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

- isolation mode;
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

Persistent volume contents, database mutations, and historical secret values
are not revisions and are not rollback-capable.

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
hints. The current `init` flow has built-in questions for the three bundled
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

Compose `configs` and `secrets` backed by `file:` are transferred as deployment
material. Local bind mounts are rejected because they depend on developer
paths and can copy source unexpectedly. Application source reaches the target
only inside images built from the declared build contexts.

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
environment.

## 5. Initialization

`lightrail init` is interactive by default and must:

1. locate the Git project root and Compose input;
2. create the first profile using `--profile` or the `preview` default, then
   ask for the target and required target settings;
3. detect Compose services, build contexts, and candidate ports;
4. ask which services are public apps and which internal port each uses;
5. create an immutable project ID and default profile;
6. select the bundled Compose plugin plus the SSH or Hetzner target plugin;
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

### 6.1 Exact hostname layout

Each public app hostname must be:

```text
<branch>.<app>.<profile>.<project>.<8-hex-ip>.<dns-domain>
```

Only `sslip.io` and `nip.io` are valid MVP DNS domains. Branch is always the
first label; app is always the second. Public mode requires a public IPv4
address; IPv6-only targets are not supported by this MVP naming contract.

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

### 6.2 Label normalization

Every branch, app, profile, and project label must:

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

Uncommitted changes do not alter a hostname. Detached HEAD uses the
`sha-<12-character-commit>` label described earlier.

### 6.3 Public HTTPS contract

There is no localhost or plain-HTTP application URL in the MVP.

- Every public app is routed by Traefik at its final hostname.
- SSH targets must reject literal loopback addresses and any hostname whose
  bounded system resolution includes loopback or IPv4-mapped loopback.
- ACME HTTP-01 obtains a certificate for each hostname.
- Port 80 must remain reachable for the HTTP-01 challenge and redirect ordinary
  HTTP traffic to HTTPS.
- Port 443 serves the application with the issued certificate.
- Lightrail must verify the final HTTPS route as part of readiness.
- Wildcard certificates and custom DNS challenges are outside the MVP.

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

1. Detect target architecture (`amd64` or `arm64`).
2. Build locally with Docker Buildx for that target.
3. Enable normal Buildx cache reuse.
4. Tag the output deterministically from environment, service, and revision.
5. Compare the local and remote Docker image IDs.
6. Compress and stream images whose remote ID differs.
7. Load them into the remote Docker engine with `docker load`.

Every `up` requests a Buildx build of build-backed services. Buildx cache and
image-ID comparison make unchanged builds inexpensive and avoid unnecessary
transfer.

Images referenced only by `image:` are pulled remotely for the target
platform. The current deployment keeps the configured reference rather than
rewriting it to a digest; after apply, the plugin records the observed image
ID and repository digests in the non-secret manifest. Strict digest pinning of
external images is therefore not yet implemented.

Lightrail transfers only:

- missing built images;
- normalized/generated Compose material;
- allowed Compose configs and secrets; and
- resolved runtime environment material.

It must not synchronize the source tree as loose files or copy persistent
volume/database data.

## 8. Targets and isolation

Profiles set:

```toml
isolation = "project" # or "machine"
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

## 10. Network boundary

Lightrail generates a private deployment override and never edits the user's
Compose files.

The generated deployment must:

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

## 11. Deployment and readiness

`lightrail up` must run these conceptual phases:

1. resolve project, branch, profile, and deterministic environment identity;
2. validate Compose, plugin compatibility, tools, configuration, and secrets;
3. preflight-inspect the target so the plugin can locate its lock authority;
4. acquire the environment mutation lock;
5. re-inspect provider/runtime state and produce the authoritative plan while
   holding that lock;
6. display the locked plan;
7. build and resolve images;
8. provision/bootstrap the target if needed;
9. transfer images and generated material;
10. apply the runtime and routing configuration;
11. wait for service and HTTPS readiness;
12. record the healthy revision and print every app URL.

`up --dry-run` remains read-only: it performs the fullest inspection and
planning available without acquiring a lock, then exits. A real `up` never
applies that pre-lock plan; it re-prepares everything under the lock.
Destruction is also re-inspected and re-planned after locking. If its action
contract changed while the user was reviewing or confirming it, `down` aborts
and asks the user to rerun it rather than applying an unconfirmed plan.

Readiness succeeds only when:

- every Compose service with a health check reports healthy;
- every service without a health check remains running through a short
  stability window;
- every public app responds through its final HTTPS hostname with a valid
  certificate;
- the default route probe receives a status below 500, allowing valid API
  responses such as 401, 403, or 404;
- an app with `health_path` and `health_status` satisfies that stricter
  requirement; and
- Compose wait and HTTPS probe phases each use a default five-minute timeout.

HTTPS checks execute concurrently. Profiles/apps may change the path, expected
status, interval, stability window, and timeouts. Because runtime apply and
exposure readiness are separate plugin requests, five minutes is not a single
wall-clock timeout for the entire `up` command.

## 12. Repeated `up` and rollback

Repeated `up` reconciles the current environment:

- routes and hostnames stay stable;
- Compose applies the new revision in place and removes orphans;
- environment-scoped named volumes are preserved;
- the previous healthy generated base, runtime override, and non-secret
  manifest remain available while the new revision is checked.

Automatic rollback is the default.

- A failed initial deployment removes resources newly created by that
  operation.
- A failed update restores the previous generated Compose documents and
  reapplies them where possible; previously loaded built images remain in the
  remote Docker cache.
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
before beginning another destroy step.

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

Only one mutating operation (`up` or `down`) may own an overlapping lock scope
at a time.

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
- A provisioning VM cannot normally be destroyed until its operation
  completes or fails.
- Mutating commands wait for up to 30 seconds by default. `--lock-timeout`
  changes that wait.
- `status`, `urls`, and `logs` are read-only and do not require the mutation
  lock.
- If a machine-isolated remote lock authority is unavailable, bypassing it
  for provider-side destruction requires `down --force` and explicit
  confirmation. Force never bypasses a busy lock and is not available for the
  shared generic SSH lock.
- Remote locks must release when their owning process/SSH session ends.

## 14. Destruction

`lightrail down` targets the current project, branch, and selected profile by
default.

Before changing anything it must:

1. rediscover owned resources;
2. display a destruction plan;
3. require interactive confirmation, unless `--yes` was provided; and
4. support `--dry-run` to stop after the plan.

For project isolation it removes the environment's containers, networks,
volumes, routes, and generated environment directory. Shared Traefik and
resources owned by other environments remain. It also removes images in the
`lightrail/*` namespace that carry the exact managed/project/environment
labels; unrelated and external images remain.

For machine isolation it deletes the managed VM and all attached
Lightrail-managed resources.

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
cannot be removed and require a later retry.

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
- Docker/Compose resources labeled with ownership and revision metadata.

Labels must carry enough information to rediscover at least project ID,
environment ID, profile, branch identity, resource role, managed ownership, and
revision where relevant.

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
- unimplemented extension points for future usage, tunnel, Fly.io,
  Kubernetes, k3s, GitHub, GitLab, and remote-state plugins.

Bundled plugins must use the same versioned JSON-RPC-over-stdin/stdout contract
as third-party plugins. Rust dynamic libraries are not a plugin ABI.

The three MVP plugins ship with Lightrail and are resolved as sibling
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
lightrail init [--from <file>] [--target ssh|hetzner] [--domain sslip.io|nip.io] [--profile <name>] [--force]
lightrail profile add <name> [--from <profile>]|list|show <name>|remove <name>|default <name>
lightrail up [--dry-run] [--keep-failed] [--lock-timeout <time>]
lightrail status [--all]
lightrail urls [--all]
lightrail logs [service] [--follow] [--tail <count>]
lightrail down [--all] [--dry-run] [--yes] [--force] [--lock-timeout <time>]
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
-n, --dry-run          display a plan without mutation (`up`, `down`)
--keep-failed          preserve a failed deployment (`up`)
-a, --all              act on project environments visible through the selected profile target
--follow               stream logs
--tail <count>          historical log records, default 100
--yes                  confirm destruction non-interactively
--force                machine-only unavailable-lock recovery for destruction
--lock-timeout <time>  mutation-lock wait, default 30 seconds
```

Followed logs handle Ctrl+C. For an in-flight `up` or `down`, the CLI sends
semantic operation cancellation, waits for the active plugin's safe stopping
point, and then performs rollback or an orderly stop as applicable. The
protocol client also cancels individually timed-out requests. Human-readable
progress and errors go to stderr; command data and `--output json` output go
to stdout. JSON log output is newline-delimited so followed logs remain
streamable. Any unsuccessful operation exits non-zero.

### 18.2 Command behavior

- `init`: discover Compose and create the project and first profile. Target and
  DNS flags can skip those interactive choices. `--force` is required to
  reconfigure and must preserve the existing immutable project ID. Users must
  destroy live environments before force-reconfiguring profiles or targets.
- `profile add|list|show|remove|default`: manage committed named profiles.
  `add` clones the `--from`, globally selected, or default profile, in that
  order. `default` changes selection when `--profile` is omitted. Removal
  refuses to orphan discovered live environments.
- `up`: plan, build, transfer, deploy, verify, then print all app URLs.
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
- `logs [service] --follow`: read or stream logs from the selected environment;
  service is optional when the runtime supports aggregate logs.
- `down`: execute the destruction contract in section 14.
  Declining the pre-mutation confirmation is a successful no-op.
- `doctor`: validate Git, the Docker client and daemon, Buildx, Compose, and
  OpenSSH. `doctor --target` additionally invokes target inspection with the
  selected profile and its credentials.
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

Deployment prerequisites are Git, Docker Engine or Docker Desktop with Buildx,
and OpenSSH. `doctor` verifies them before deployment.

Remote targets are Linux `amd64` or `arm64`. Generic automatic bootstrap
initially supports Ubuntu and Debian families. Hetzner uses a supported Ubuntu
image by default.

Lightrail detects remote architecture and builds only that platform. A
cross-architecture build uses Buildx/QEMU. If the local builder cannot provide
the target platform, deployment fails with exact remediation instructions.

## 20. Deferred roadmap

None of the features below is implemented. The plugin and profile model
preserves extension points for:

- authenticated private tunnels with no public inbound application ports;
- Fly.io through an agentless target plugin;
- Kubernetes and k3s runtimes, ingress, and readiness;
- GitHub/GitLab pull-request event automation while retaining the current-CWD
  workflow;
- provider-aware usage and cost reporting;
- blue/green or rolling updates;
- custom DNS plugins outside the MVP;
- remote state backends; and
- native Windows developer support.

Deferred features must not weaken MVP invariants. In particular, future private
mode must not quietly expose public ports, and future CI automation must not
make GitHub a requirement for local current-worktree deployment.
