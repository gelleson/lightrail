# Lightrail architecture

Status: implemented MVP architecture. The code and automated tests exercise
the component boundaries described here. See the README for current
live-validation status; this document intentionally keeps the component model
independent of dated smoke-test results.

The protocol supports request cancellation and the client cancels timed-out
requests. Followed logs stop on Ctrl+C. During `up` and `down`, Ctrl+C sends
`plugin.cancel` for the logical operation and waits for the active plugin to
reach a safe stopping point. A cancelled `up` then follows the ordinary
rollback path unless `--keep-failed` was selected.

## 1. Architectural stance

Lightrail is a local orchestrator, not a platform service.

```text
current Git worktree
        |
        v
+----------------------+       versioned JSON-RPC       +--------------------+
| lightrail CLI + core | <----------------------------> | plugin executables |
|                      |                                 |                    |
| identity / config    |                                 | source / builder   |
| plan / journal       |                                 | target / runtime   |
| retry / rollback     |                                 | exposure / DNS     |
+----------+-----------+                                 +----------+---------+
           |                                                        |
           | local Buildx, SSH, provider APIs                        |
           v                                                        v
+--------------------------------------------------------------------------+
| remote target                                                           |
|                                                                          |
| Docker Engine + Compose + Traefik (MVP)                                  |
| labels + ordinary provider resources; no Lightrail agent or daemon       |
+--------------------------------------------------------------------------+
```

The core coordinates. Plugins perform infrastructure-specific work. Durable
truth lives in committed configuration plus labeled provider/runtime
resources. `.lightrail/` improves recovery and diagnostics but is never the
only way to find an environment.

## 2. Component boundaries

### 2.1 CLI

The CLI owns:

- command parsing and help;
- precedence of command flags, environment variables, project configuration,
  and defaults;
- interactive initialization and confirmation;
- human output, JSON output, progress, and exit status;
- Ctrl+C termination of followed log streams and semantic cancellation of
  active mutations;
- dispatch to application use cases.

Data output belongs on stdout. Progress, diagnostics, and errors belong on
stderr so commands remain pipeable.

### 2.2 Core domain

The provider-independent core owns validated concepts:

- project ID and slug;
- profile and app selection;
- branch and environment identity;
- normalized DNS labels and hostnames;
- deployment revision;
- plan and action journal;
- resource ownership observations;
- operation outcome and rollback intent.

The core enforces cross-plugin invariants. For example, it verifies that a
profile has compatible target/runtime/exposure capabilities. `init` and the
Compose plugin verify that an app's service and port exist. Provider-specific
fields remain opaque, plugin-validated values rather than being embedded in
core types.

### 2.3 Orchestrator

The orchestrator executes capability plans in a fixed safe order. It owns:

- plugin discovery and compatibility checks;
- preflight validation before remote mutation;
- operation lock acquisition;
- capability ordering and plugin-owned action dependencies;
- per-action journal records;
- transient/permanent error handling;
- readiness aggregation;
- rollback or failed-resource preservation.

An operation has one active mutation owner. Read-only inspection can run
without taking that lock.

### 2.4 Plugin host

The plugin host:

- verifies checksums for third-party executables pinned in `lightrail.lock`;
- locates bundled executables beside the CLI and verifies their declared
  package version;
- starts it with a sanitized process environment;
- performs the protocol handshake;
- validates its ID, version, exact pinned protocol, negotiated protocol range,
  manifest, and capabilities;
- sends only selected configuration and declared secret values;
- multiplexes requests, progress notifications, cancellation, and errors;
- treats stdout as protocol-only and stderr as plugin diagnostics;
- terminates the child at the end of the command/session.

Plugins are native trusted executables, not in-process Rust dynamic libraries.
Their implementation language is irrelevant.

### 2.5 Bundled MVP plugins

Three bundled executables implement the pipeline:

- `dev.lightrail.compose` advertises `source`, `builder`, `runtime`,
  `exposure`, and `dns`. It resolves the current Compose project, builds with
  Buildx, transfers images, generates the remote deployment, manages Traefik,
  derives IP-DNS hostnames, checks HTTPS readiness, and reads logs.
- `dev.lightrail.ssh` advertises `target` and `operation-lock`. It inspects or
  bootstraps a generic Ubuntu/Debian host, validates public ports and firewall
  observations, returns transport state, and holds a host-wide remote lock
  using an atomic POSIX `mkdir` owned by the SSH session. It does not require
  the remote `flock` utility.
- `dev.lightrail.hetzner` advertises `target` and `operation-lock`. It manages
  one labeled server and firewall per environment through the Hetzner Cloud
  API, discovers project-wide resource sets, uses cloud-init for the Docker
  baseline, and holds connection-scoped remote locks on reachable managed
  machines.

The profile assigns the Compose executable to five independent capability
slots and one target executable to the target slot. Bundled plugins use the
same process protocol as third-party plugins; they are located as sibling
executables and do not need lock-file entries. Resolution canonicalizes an
absolute sibling path and fails closed if it is missing; release builds never
fall back to a same-named executable from `PATH`.

## 3. Data and state

### 3.1 Committed state

`lightrail.toml` defines project intent. `lightrail.lock` pins third-party
executable identity, version, source, protocol, and checksum; bundled plugin
selection is represented directly by its stable ID in `lightrail.toml`. Both
files are portable across developers and CI.

The project ID is immutable. Human names are not used as sole ownership keys.

### 3.2 Local ephemeral state

`.lightrail/` currently holds replaceable operation journals and the local
secret-name index used by the keyring integration. It may grow additional
non-secret caches and diagnostics without becoming authoritative. The prior
healthy deployment documents and non-secret manifest are held on the remote
target, not in local state.

It must not hold secret values. It must be safe to lose. A fresh machine with
the repository and credentials must be able to rediscover, update, inspect, and
destroy environments.

The resolved Compose document used by `up` is a process-lifetime temporary
file. Core creates it with `docker compose config --format json`, preserving
the invoking shell, `.env`, `env_file`, and Compose interpolation behavior,
and keeps the file alive while the plugins validate, plan, and apply. It is
deleted automatically when the operation ends and is not copied into
`.lightrail/`.

### 3.3 Authoritative remote observations

Provider and Docker resources carry ownership labels. The semantic label set
must include:

- managed-by Lightrail;
- immutable project ID;
- deterministic environment ID;
- profile identity;
- branch identity;
- resource role;
- app/service identity where applicable;
- deployment revision where applicable.

Exact label key serialization belongs to the implementation protocol, but all
plugins must round-trip these semantics. A target's `inspect` operation returns
observations, not assumptions derived solely from local cache.

For `status --all` and `urls --all`, Compose aggregates
`state.environments` from exact Docker labels and owned remote manifests
visible through the selected profile's configured target. A machine-isolated
target instead returns `state.targets`; core fans runtime inspection out to
each labeled machine returned by that provider configuration, merges
environment metadata and endpoints, and keeps an unreachable machine visible
as a degraded summary. Profiles using a different host or provider credential
boundary require a separate query.

### 3.4 Deterministic identity

The environment ID is a deterministic digest or equivalent stable encoding of:

```text
immutable project ID + profile identity + current branch identity
```

Dirty state and commit changes affect a revision, not this ID. Resource names
may contain a readable prefix, but uniqueness and ownership rely on the stable
ID.

## 4. Deployment pipeline

### 4.1 Phase graph

```text
discover CWD / Git / config
             |
             v
validate Compose / plugins / tools / secrets
             |
             v
inspect target and runtime -----> compute plan -----> dry-run exits here
             |
             v
acquire authoritative mutation lock
             |
             v
re-inspect + compute authoritative plan
             |
             v
build locally + provision/bootstrap remotely
             |
             v
resolve/pull images + stream missing built images
             |
             v
apply Compose + Traefik routes + ACME
             |
             v
service checks + concurrent final HTTPS probes
             |
       +-----+------+
       |            |
     healthy       failed / cancelled
       |            |
       v            v
commit revision   automatic rollback
print URLs        or preserve with --keep-failed
```

Validation that can be completed locally occurs before provisioning. The
first target inspection establishes how to reach the lock authority. For a
real `up`, all state displayed and applied is re-inspected and re-planned while
the lock is held. `down` similarly re-inspects and re-plans after locking, and
aborts if the destructive plan differs from the plan the user confirmed.
Immediately before each mutating plugin call, the core reacquires the same
scope and owner and requires the exact original opaque token. A missing or
different token aborts before that mutation; a newly returned different token
is released.
`--dry-run` remains read-only and stops after the best complete plan obtainable
without acquiring a mutation lock. The operation journal records planned and
completed action IDs without secret payloads.

### 4.2 Planning contract

Each mutating plugin capability exposes `plan`, `apply`, `inspect`, and
`destroy` where applicable.

A plan describes:

- resources to create, update, retain, and remove;
- dependencies between actions;
- which actions are shared versus environment-owned;
- reversibility/compensation behavior;
- required credentials and external prerequisites;
- human-readable risk and destructive effects.

The core combines capability plans and rejects conflicts before apply.
`--dry-run` prints the complete plan obtainable without mutation. A plugin must
not hide mutation inside inspection or planning. Plans used for mutation are
authoritative only after the core re-prepares them under the target lock.

### 4.3 Build boundary

Buildx runs on the developer machine against the current worktree. The target
architecture is discovered before the build.

The output boundary is a deterministic revision tag plus its Docker image ID:

```text
current build context --Buildx--> target-platform tagged image
                                      |
                                      +-- same remote image ID: reuse
                                      |
                                      +-- different/missing: stream -> docker load
```

No registry push is required for locally built services. The remote machine
does not receive a source-tree checkout. External `image:` references are
pulled remotely for the target platform and remain as configured references in
the deployment. Their observed image IDs and repository digests are recorded
after apply; strict digest
rewriting is not implemented.

### 4.4 Generated deployment

The Compose runtime plugin consumes the ephemeral resolved document and
creates generated base and override documents. It:

- uses deterministic Compose project names;
- replaces local build declarations with deterministic revision image tags;
- removes published host ports;
- scopes networks and named volumes;
- attaches selected apps to an ingress network;
- adds ownership and revision labels;
- extracts service environments from the persistent base and puts them in a
  temporary environment override;
- rejects bind mounts and host networking; and
- removes orphans when reconciling.

The user's Compose files remain unchanged. The generated remote base, runtime
override, and non-secret manifest are written with mode `0600`. The temporary
environment override is also mode `0600`, is included only for `docker compose
up`, and is removed immediately after Compose has created the containers,
whether apply succeeds or fails. The non-secret manifest clears application
environment maps. Referenced Compose `configs` and `secrets` files are
uploaded separately with mode `0600`.

## 5. Remote topology

### 5.1 Shared generic SSH host

```text
internet :80/:443
        |
        v
  shared Traefik
     |        |
     |        +--- env B ingress network ---> env B public apps
     |
     +------------ env A ingress network ---> env A public apps
                         |
                         +--- env A private services
```

Traefik is shared infrastructure and joins a distinct external ingress network
for each environment. The default configured prefix is `lightrail-ingress`,
but the concrete network is
`<prefix>-<deterministic-environment-id>`. Public services also join their
environment's private application network; private services join only that
application network. App containers from different branches therefore do not
share a general-purpose or ingress network.

Remote ownership is separated into:

- shared host resources, retained until explicitly uninstalled; and
- environment resources, destroyed by that environment's `down`.

### 5.2 Dedicated Hetzner machine

```text
Hetzner VM (one environment)
├── managed firewall
├── Docker Engine + Compose
├── Traefik
├── environment networks and volumes
└── public apps + private services
```

The machine is itself environment-owned. Destroying the environment removes
the VM and attached managed resources. The deterministic name and labels make
an interrupted create operation discoverable and prevent duplicate machines.

## 6. Routing and certificate lifecycle

The core derives one route for every selected app:

```text
branch.app.profile.project.8hexip.sslip.io
```

or the identical prefix under `nip.io`.

The exposure plugin configures Traefik to:

1. accept the final hostname on port 80;
2. serve ACME HTTP-01 challenge material;
3. redirect other HTTP requests to HTTPS;
4. terminate TLS on port 443; and
5. proxy to the app's internal Compose port.

An environment is not ready until the final route returns the expected status
over HTTPS with a valid certificate. This makes DNS resolution, port reachability,
certificate issuance, Traefik routing, and application reachability part of a
single observable success condition.

## 7. Secrets path

```text
secret reference in lightrail.toml
               |
               v
environment override -> OS keyring -> interactive prompt
               |
               v
core redaction boundary
               |
               +--> only declaring plugin, over JSON-RPC stdin
               |
               +--> 0600 remote temp material when required
                           |
                           +--> deleted after container creation
```

Secrets are never placed in argv or persisted in configuration, locks,
journals, plans, or generated diagnostic output. Protocol secret wrapper
diagnostics render as `[REDACTED]`; plugin authors are also responsible for
never writing received values to stderr or structured diagnostics.

A plugin normally lists every secret name it may receive. Protocol version
1.0.0 also supports a manifest requirement named `"*"`. This is a constrained
wildcard, not access to the keyring: core scans only the selected capability's
configuration and, only for an `up` runtime operation, the desired app
environment. It resolves only explicit `{ secret = "name" }` references found
there and sends only those values to that plugin. The runtime context retains
them only for a possible rollback within the same `up`. Status, URL, log, and
standalone `down` operations therefore neither prompt for nor transmit
application secrets. `dev.lightrail.compose` declares an optional wildcard so
arbitrary application secret references can reach the runtime during `up`
without granting access to unreferenced secrets. Exact required declarations
remain operation inputs when needed; `dev.lightrail.hetzner`, for example,
declares the required provider credential `hetzner-token`.

Container environment variables remain inspectable by a privileged Docker
operator; Lightrail documents this limitation and supports file-backed Compose
secrets when the application can use them.

## 8. Bootstrap lifecycle

Bootstrap is an idempotent target concern:

1. inspect OS, architecture, privileges, Docker/Compose versions, ports, and
   directories;
2. classify the host as ready, safely bootstrap-able, unsupported, or
   incompatible;
3. in automatic mode, install only missing supported components;
4. in verification mode, report remediation without installation;
5. converge the configured remote root and the prerequisites for remote locks;
6. verify readiness after changes.

An incompatible existing Docker or Traefik installation is not overwritten
blindly. The Compose plugin, rather than target bootstrap, reconciles shared
Traefik and per-environment ingress networks. Generic SSH does not rewrite an
unknown firewall. Hetzner bootstrap uses cloud-init and then verifies the same
Docker postconditions.

## 9. Readiness model

Readiness is an aggregate:

```text
all Compose services
├── explicit healthcheck -> healthy
└── no healthcheck        -> running for stability window

all public apps
└── final HTTPS hostname -> valid TLS + status < 500
                            or configured exact status/path
```

Final HTTPS checks run concurrently. Compose apply and endpoint readiness each
use a default five-minute timeout, so that value is not a single wall-clock
deadline for the entire `up` command. A timeout, unhealthy service, invalid
certificate, routing failure, or unexpected response fails the revision and
enters rollback.

## 10. Failure and rollback architecture

Every applied action records:

- stable action ID;
- owning capability/plugin;
- resource observations before and after;
- completion state;
- compensation or destroy intent;
- error classification;
- no secret material.

Failures are classified as:

- transient: bounded retry with backoff;
- permanent: fail immediately with actionable context;
- cancellation: represented by the protocol for request timeouts, plugin
  coordination, and CLI Ctrl+C handling at mutation safe points.

Initial deployment rollback destroys capabilities that were absent before the
operation, in reverse apply order. Update rollback restores and reapplies the
previous generated Compose base and runtime override where possible;
previously loaded built images remain in the remote Docker cache. The temporary
application-environment override is not retained; rollback can re-render
currently resolvable references, but it cannot recover historical secret
values or environment values that have since changed. Mutable external image
tags are likewise outside the guarantee. Cleanup continues after individual
compensation failures and reports the failures.

Rollback is infrastructure/application-revision rollback, not a transaction
over application data. Database migrations, volume writes, external side
effects, and unavailable old secrets are explicitly outside its guarantee.

`--keep-failed` disables compensation for debugging and records the failure in
the local operation journal.

## 11. Locking

Locks protect the complete mutation aggregate, not merely a local process.
The protocol names that aggregate with a scope and stable scope ID:

- `environment` protects one branch/profile environment;
- `project` protects every environment owned by one immutable project ID; and
- `target` protects shared target-wide resources.

Generic SSH uses `target` scope because branch environments share one host and
Traefik instance. It holds the host-wide
`/tmp/lightrail-host.operation.lock` directory created atomically by POSIX
`mkdir`; the SSH process keeps stdin open and removes the directory on normal
release or session exit. No remote `flock` installation is required.

Hetzner uses `environment` scope for one machine and `project` scope for
project-wide operations. It snapshots the exact labeled servers and firewalls
before locking, prevents overlapping session-local scopes, and holds remote
`flock` processes on every reachable machine in that scope. A first provision
starts with the session reservation because no VM exists yet, then upgrades
that same token to the VM's remote lock as soon as bootstrap is ready. If the
upgrade loses authority, the new provider resources are preserved for
explicit recovery instead of being deleted without a lock. Project-wide
operations acquire each machine's lock in deterministic provider-ID order;
separate environment locks therefore still allow different branch machines
to reconcile concurrently. Provider IDs and ownership labels are verified
again before deletion.

The default acquisition timeout is 30 seconds. Read-only operations need no
lock. `down --force` may bypass the lock only for machine isolation when the
remote lock authority returns `unavailable`; it still requires explicit user
confirmation. It never bypasses a busy/held lock, and a shared generic SSH
host never uses this bypass.

## 12. Destruction model

Destruction is discovery-driven and ownership-scoped:

```text
inspect labeled resources -> render destruction plan -> confirm -> destroy
                                      |
                                      +--> --dry-run stops
```

Plugins must prove ownership before deletion. Project isolation excludes
shared resources and other environments. Machine isolation includes the
entire environment-owned VM. Steps are idempotent so an interrupted `down` can
continue from observed state rather than trusting a stale journal.

`down --all` expands the selected target's ownership query from one
environment to the immutable project ID and therefore requires stronger
confirmation. On a shared SSH host it removes exactly owned containers,
volumes, networks, generated environment directories, and labeled
`lightrail/*` images while retaining shared Traefik. On a Hetzner profile it
deletes every project-labeled server and firewall visible through that
profile's provider configuration, including resources belonging to branches
other than the current checkout. A different profile target or credential
boundary is outside that invocation and must be cleaned separately.

If an environment manifest is missing, Compose does not infer absence from
that file alone. It queries containers, networks, volumes, and `lightrail/*`
images using the exact managed, project-ID, and environment-ID labels. Any
match is reported as degraded state so a subsequent `down` performs the same
exact-label cleanup. Project-wide image discovery filters owned image IDs,
re-inspects their labels and repository tags, and therefore also finds an
image-only orphan. A present manifest must match the immutable operation
project and environment IDs before it can authorize inspection or deletion.

`down --force` still requires confirmation and never deletes the shared SSH
host. For a Hetzner machine profile it can skip unreachable runtime cleanup
and delete only provider resources matching immutable ownership labels.

## 13. Security boundaries

The MVP security model is explicit:

- A plugin executable is trusted native code with the user's permissions.
- Bundled executables must resolve to canonical trusted sibling paths; a
  missing binary is an error, not permission to search `PATH`.
- Third-party SHA-256 pinning detects a changed plugin artifact; it is not a
  sandbox.
- Only explicit plugin install/update/remove commands change third-party pins.
- Remote SSH access and provider credentials grant infrastructure authority;
  least-privilege credentials and operator CIDRs remain user responsibilities.
- Only ports 80/443 and constrained SSH are exposed on managed Hetzner
  firewalls.
- App ports are not published directly.
- Both the target and Compose transports resolve SSH hostnames with a bounded
  preflight and reject any loopback or IPv4-mapped-loopback candidate.
- Generic SSH firewall state is validated but not rewritten.
- Secret wrapper diagnostics are redacted, and bundled plugins must keep
  plaintext out of logs, plans, errors, journals, and JSON output.
- Provider/runtime labels are ownership evidence, but destructive operations
  must also constrain queries to the selected target/account and project ID.

## 14. Deferred extension points

The following capabilities are not implemented. Their intended attachment
points are:

| Future feature | Extension point |
| --- | --- |
| Fly.io | target/runtime/exposure plugins |
| Kubernetes or k3s | target/runtime/ingress/readiness plugins |
| authenticated private access | exposure/tunnel plugin |
| GitHub/GitLab PR automation | source/event plugin |
| usage and cost reports | observation/usage plugin |
| blue/green updates | runtime strategy capability |
| remote state | state backend plugin |
| custom DNS | DNS plugin outside MVP policy |

The core continues to own identity, orchestration, trust checks, typed secret
transport, and user-facing command behavior. A future implementation must not
move those invariants into one provider plugin or introduce a mandatory
control plane.
