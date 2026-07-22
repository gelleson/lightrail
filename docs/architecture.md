# Lightrail architecture

Status: implemented local-first architecture. The code and automated tests
exercise the component boundaries described here. See the README for current
live-validation status; this document intentionally keeps the component model
independent of dated smoke-test results.

The protocol supports request cancellation and the client cancels timed-out
requests. Followed logs stop on Ctrl+C. During `up`, `down`, and `prune`,
Ctrl+C sends `plugin.cancel` for the logical operation and waits for the active
plugin to reach a safe stopping point. A cancelled `up` then follows the
ordinary rollback path unless `--keep-failed` was selected.

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
           | local Buildx, SSH, kubectl, provider APIs               |
           v                                                        v
+--------------------------------------------------------------------------+
| remote target                                                           |
|                                                                          |
| Docker/Compose/Traefik, existing Kubernetes, or Fly Apps/Machines        |
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

### 2.5 Bundled plugins

Five bundled executables implement the pipeline:

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
- `dev.lightrail.kubernetes` advertises `builder`, `target`, `runtime`,
  `exposure`, `dns`, and `operation-lock`. It builds locally, pushes
  deterministic OCI images, and reconciles ordinary namespaced resources
  through an explicit existing kube context. It uses Kubernetes Lease locks
  and never creates or resizes clusters or nodes.
- `dev.lightrail.fly` advertises `builder`, `target`, `runtime`, `exposure`,
  `dns`, and `operation-lock`. It builds locally, pushes provider-reachable
  images, and manages exactly owned Fly Apps, Machines, volumes, proxy routes,
  and native endpoints through Fly APIs without a remote agent.

SSH/Hetzner profiles assign the Compose executable to source, builder,
runtime, exposure, and DNS slots and the provider executable to target.
Kubernetes/Fly retain Compose only as the local source resolver and assign the
provider executable to builder, target, runtime, exposure, and DNS. Bundled
plugins use the same process protocol as third-party plugins; they are located
as sibling executables and do not need lock-file entries. Resolution
canonicalizes an absolute sibling path and fails closed if it is missing;
release builds never fall back to a same-named executable from `PATH`.
Kubernetes and Fly additionally advertise the namespaced
`dev.lightrail.selected-destroy.v1` behavior feature so core can safely use
the existing plan/destroy methods for an exact expiry selection. Plugins
without that feature cannot participate in `prune`.

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
healthy Compose deployment documents and non-secret manifest are held on the
remote SSH/Hetzner target, not in local state. Kubernetes and Fly observations
come from provider-visible resources and metadata.

It must not hold secret values. It must be safe to lose. A fresh machine with
the repository and credentials must be able to rediscover, update, inspect, and
destroy environments.

The resolved Compose document used by `up` is a process-lifetime temporary
file. Core creates it with `docker compose config --format json`, preserving
the invoking shell, `.env`, `env_file`, and Compose interpolation behavior,
and keeps the file alive while the plugins validate, plan, and apply. It is
deleted automatically when the operation ends and is not copied into
`.lightrail/`.

Local asynchronous tool calls run with null stdin, captured separate
stdout/stderr, a hard deadline (ten minutes by default, overridable per call),
kill-on-drop, and explicit terminate-and-reap cleanup on deadline or caller
cancellation.
The synchronous, read-only Git discovery calls use separate anonymous capture
files, disable terminal prompts and optional locks, enforce a 30-second
deadline, and explicitly terminate and reap Git on timeout.

### 3.3 Authoritative remote observations

Provider, Docker, Kubernetes, and Fly resources carry ownership labels or
provider-equivalent metadata. The semantic ownership set must include:

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

For `status --all` and `urls --all`, plugins return `state.environments` from
exact ownership metadata visible through the selected profile's configured
target. Compose derives those entries from Docker labels and owned remote
manifests. Kubernetes derives them from project-labeled namespaces in the
selected context; Fly derives them from owned resources in the selected
organization/account boundary. A machine-isolated target instead returns
`state.targets`; core fans runtime inspection out to each labeled machine,
merges environment metadata and endpoints, and keeps an unreachable machine
visible as a degraded summary. Profiles using a different host, context,
organization, or credential boundary require a separate query.

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
build locally + target preflight/provision where supported
             |
             v
resolve images + stream to Docker or push OCI references
             |
             v
apply Compose/Traefik or provider-native runtime/routes
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
completed action IDs under their plugin, capability, and exact plan ID without
secret payloads. Mutation journals, including `down` and `prune`, are populated
from the exact locked plans. A destroy result completes only the action IDs it
returns, unless it proves that the capability was destroyed with no remaining
state.

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
When a user-reviewed destructive plan must remain continuous across lock
acquisition, core canonicalizes and hashes the complete serialized
`PlanResult`, not only its plan ID or visible action summaries. Actions,
dependencies, rollback declarations, and opaque non-secret plugin metadata all
participate in that continuity check.

A provider action that may mutate must attach rollback metadata declaring
either a supported exact inverse or `supported: false` with a non-secret
reason. Omission is reserved for genuinely side-effect-free actions. Builder
artifacts that are intentionally retained still declare an unsupported inverse
explicitly; core then treats them as cache rather than an environment rollback
failure.

### 4.3 Build boundary

Buildx runs on the developer machine against the current worktree. The target
platform is discovered or validated before the build.

The output boundary is a deterministic revision tag plus target-specific
delivery:

```text
current build context --Buildx--> deterministic target-platform image
                                      |
                                      +-- SSH/Hetzner: compare image ID
                                      |                 then stream/load
                                      |
                                      +-- Kubernetes/Fly: push OCI reference
                                                           then provider pulls
```

SSH/Hetzner do not require a registry push for locally built services.
Kubernetes requires a provider-reachable registry and authenticated local
push; its pull authorization is a separate cluster prerequisite. Fly uses its
typed provider token in an isolated Docker configuration for
`registry.fly.io` and resolves built tags to immutable digests before Machine
deployment. No target receives a source-tree checkout. External `image:`
references are pulled by the target runtime and remain as configured
references in the deployment; strict digest rewriting is not implemented.
Registry images are build artifacts/cache outside the environment aggregate
and remain after `down`.

Every provider validates local build contexts and Dockerfiles against the
operation context's canonical Git root, including symbolic-link resolution,
and represents them project-relatively in revision input. Because Git cannot
prove that ignored files are absent from Docker's context, every local-build
revision is also scoped to its `up` operation. This changes the deterministic
tag between operations while preserving Buildx's content-addressed layer
cache.

### 4.4 Generated runtime

For SSH/Hetzner, the Compose runtime plugin consumes the ephemeral resolved
document and creates generated base and override documents. It:

- uses deterministic Compose project names;
- replaces local build declarations with deterministic revision image tags;
- removes published host ports;
- scopes networks and named volumes;
- attaches selected apps to an ingress network;
- adds ownership and revision labels;
- extracts service environments from the persistent base and puts them in a
  temporary environment override;
- validates file-backed configs/secrets inside the granted Git root;
- rejects bind mounts, host networking, custom network topology, and custom
  named-volume options; and
- removes orphans when reconciling.

The user's Compose files remain unchanged. The generated remote base, runtime
override, and non-secret manifest are written with mode `0600`. The temporary
environment override is also mode `0600`, is included only for `docker compose
up`, and is removed immediately after Compose has created the containers,
whether apply succeeds or fails. The non-secret manifest clears application
environment maps. Referenced Compose `configs` and `secrets` files are
uploaded separately with mode `0600`.

Before hashing, the Compose runtime removes checkout and temporary paths,
normalizes Compose-generated project/default-network/volume names, and replaces
resolved and explicit application environment values with non-secret
key/reference shape. Local builds, environment-bearing services/apps, and
file-backed configs/secrets are operation-scoped so changed hidden bytes
reconcile without a plaintext-derived provider revision label. The same
operation ID keeps locked plan and apply revision computation stable.

For Kubernetes, the provider plugin consumes the same resolved source intent
and renders ordinary Namespace, Secret, PVC, Service, Deployment or
StatefulSet, explicit job, and Ingress resources. It applies them through
`kubectl --context` and an optional explicit absolute kubeconfig path. The
configured existing IngressClass and required existing cert-manager
ClusterIssuer are authoritative; the issuer must report Ready and contain an
HTTP-01 solver. The plugin does not install or rewrite shared components.
NGINX routes get explicit SSL-redirect annotations.
Traefik routes get a namespace-owned RedirectScheme Middleware after the
plugin verifies the `traefik.io/v1alpha1` or legacy
`traefik.containo.us/v1alpha1` Middleware CRD. The redirect-only and TLS
Ingresses use the configured existing Traefik entrypoints, defaulting to
distinct `web` and `websecure` names. Generated Secrets contain only resolved
app environment references sent over stdin; Compose
`configs`/`secrets`, privileged containers, host networking, and bind mounts
are rejected. The translator uses a closed service-field set, accepts only the
normalized implicit Compose `default` network, and rejects custom/external
network semantics. Named volumes must remain environment-owned with generated
names; external volumes, custom names, drivers, and driver options fail
validation. The operation context's granted Git root is the sole source
authority. Existing build contexts and explicit Dockerfiles are resolved
through symbolic links, checked for containment, and represented
project-relatively in the clean revision hash. Only after strict validation
does revision canonicalization remove directory-derived Compose project,
default-network, and named-volume names. Every local-build revision is also
operation-scoped because Git cannot prove that ignored files are excluded from
Docker's context; Buildx retains content-addressed layer reuse. Canonical
revision input retains environment key shape but removes all resolved
environment values, so no plaintext-derived digest enters provider metadata.
Every non-Job service gets private cluster DNS; a service with no declared
port gets a selector-backed headless Service rather than a guessed port.
Completed Jobs remain until namespace teardown and have no Job TTL. Unchanged
image-only Jobs are repeatable; an existing local-build Job requires
`down`/`up` on every later operation because operation-scoped image identity
changes its immutable spec. Long-running workloads backed by generated
environment Secrets receive a non-secret operation-derived Pod-template
revision once per `up`, making changed values take effect without hashing or
retaining secret plaintext in metadata. Selected or discovered platforms
constrain image builds and Pod placement: one architecture renders a node
selector and multiple architectures render required node affinity.

Kubernetes reconciliation is intentionally conservative. `up` refuses a
desired model that would remove an owned resource, add a runtime resource to
an environment with an observed prior revision, or replace a changed immutable
Job; the operator must review `down` and then create the new topology with
`up`. Existing Deployment and StatefulSet mutations advertise an unsupported
inverse because retaining complete live manifests could retain injected
secret-bearing fields. A later failure therefore reports their runtime update
as rollback-incomplete. Initial namespace cleanup plus exact Exposure and
DNS-expiry inverses remain supported.
Destructive namespace deletion advertises an explicit unsupported inverse:
Kubernetes cannot reconstruct deleted workloads, Secrets, PVC objects, or
application data exactly.

For Fly, the provider plugin renders exactly owned Apps, Machines, volumes,
and Fly Proxy configuration and applies them through the Fly APIs. Provider
tokens remain on the JSON-RPC stdin secret path, not command arguments or
ambient child environment. It creates one App per Compose service; all
environment Apps join the same deterministic custom 6PN membership boundary,
which is not a separately managed network object. It gives public addressing
only to selected apps by allocating a shared IPv4. The initial translator
supports at most one named volume per Machine and requires an explicit region
when a volume is present. It requires
list-form Compose `command`/`entrypoint` and rejects bind/external volumes,
host networking, privileged services, `env_file`, Compose
`configs`/`secrets`, unsupported service/deploy fields, and application secret
references. Private discovery uses each deterministic Fly App name beneath
`.internal`, not the original Compose service alias. The existing
environment's exact service/App set is a continuity boundary: an addition or
removal requires explicit `down` then `up`. Named-volume topology, Machine
region, requested volume size, and public-to-private changes have the same
boundary, while ordinary in-place revisions retain those Apps. The current
resource model requires exactly one Machine per App. Compose `healthcheck`
remains revision metadata but is not translated. Lightrail app health fields
are authoritative for generated Machine checks and final HTTPS readiness, and
a configured health status is limited to 2xx. Private services receive no
public Fly service or check. Proxy-backed public services receive the
configured autostop/autostart behavior. Private service Machines have no Proxy
wake trigger and remain running under their restart policy. Existing Machine
updates advertise no exact previous-revision inverse, so a failed update is
reported as rollback-incomplete.

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

### 5.3 Existing Kubernetes cluster

```text
existing cluster
├── existing control namespace
│   └── Lightrail Lease locks
├── existing ingress controller / IngressClass
│   └── exact configured LoadBalancer Service
└── one owned namespace per environment
    ├── workloads, Services, Secrets, and jobs
    ├── persistent volume claims
    └── selected public-app Ingress routes
```

The namespace is the environment destruction boundary. The cluster, nodes,
control namespace, RBAC, ingress controller, ClusterIssuer, registry, and
registry images are shared prerequisites and remain. Only selected public apps
receive Ingress routes; other Services stay cluster-private. Every non-Job
service has a private DNS name, including a selector-backed headless Service
when it has no declared port.

### 5.4 Fly

```text
Fly organization/account boundary
└── one deterministic owned environment aggregate
    ├── one App/Machine workload per Compose service
    ├── one environment-specific custom 6PN membership
    ├── persistent volumes
    └── selected public-app Fly Proxy routes and fly.dev endpoints
```

The provider resource aggregate is the environment destruction boundary. It
is discovered from immutable ownership metadata rather than local state.
The 6PN name is an App membership/isolation boundary, not a separately managed
or deleted resource. There is no remote Lightrail process or SSH bootstrap.

## 6. Routing and certificate lifecycle

SSH/Hetzner derive one route for every selected app:

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

Kubernetes uses the exact configured existing IngressClass when its controller
is NGINX or Traefik; other controller types fail validation. It reads the
ingress address from the exact configured LoadBalancer Service backing that
class and, for a public IPv4, derives the same branch-first/app-second
hexadecimal `sslip.io`/`nip.io` hostname. A hostname-only load-balancer status
is not assumed to delegate arbitrary child names and therefore fails with
remediation. The plugin never guesses among Services. NGINX gets explicit
redirect annotations; Traefik gets an environment-owned, namespace-qualified
RedirectScheme Middleware using the detected current or legacy CRD. Final
readiness checks both trusted HTTPS and same-host HTTP-to-HTTPS redirect. Fly
uses provider-native `fly.dev` endpoints and Fly Proxy TLS. One Fly App is
created per Compose service; a public App name uses the configured prefix, a
stable immutable-project marker, normalized branch, normalized app, and a
stable resource suffix in that order. Callers obtain the final value from
`lightrail urls` instead of reconstructing it.

An environment is not ready until every final route returns the expected
status over HTTPS with a valid certificate. This makes DNS resolution, public
reachability, certificate issuance, routing, and application reachability
part of one observable success condition.

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

The Kubernetes plugin receives only explicitly referenced application secrets
needed for `up` and submits generated Secret material through `kubectl` stdin.
Its optional kubeconfig path is explicit and absolute; only the Kubernetes
child may additionally inherit `KUBECONFIG`. Registry push credentials remain
in the local Docker credential boundary, while cluster image-pull
authorization is an existing cluster Secret or policy selected by name;
Lightrail does not copy the local registry credential into namespaces.
Generated app Secrets persist in the Kubernetes API until namespace deletion;
RBAC, API auditing, and etcd encryption are cluster-operator boundaries.

The Fly plugin declares `fly-token` as its required provider credential. Core
sends it only through JSON-RPC stdin to the Fly capabilities; the sanitized
child environment does not inherit a Fly API token variable.

## 8. Bootstrap lifecycle

SSH/Hetzner bootstrap is an idempotent target concern:

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

Kubernetes has preflight but no bootstrap/setup phase. It verifies access
through the explicit context, reads the existing control namespace and
IngressClass, discovers architectures from Ready, schedulable Linux nodes,
and observes the exact configured LoadBalancer Service backing that class. An
explicit `platforms` set must be a subset of those observed architectures. The
Service namespace is a DNS subdomain and its name is a DNS label; both are
required, so the plugin never guesses among controller Services.
Lease/resource RBAC, registry pull, the required ClusterIssuer, an optional
image-pull Secret, admission, and storage requirements remain operator
prerequisites and may fail before or during their first exact use. Lightrail
never creates or resizes the cluster or nodes and never installs shared
components.

Fly preflight validates the organization, optional region, provider
credential, platform, and API access. Fly remains agentless and does not
install software on Machines.

## 9. Readiness model

Readiness is an aggregate:

```text
runtime
├── Compose: healthcheck or running stability window
├── Kubernetes: concurrent workload rollouts + Job completion
└── Fly: required Machine/provider state

all public apps
└── final HTTPS hostname -> valid TLS + status < 500
                            or configured exact status/path
```

Final HTTPS checks run concurrently. Runtime apply/readiness and endpoint
readiness are separately bounded, so one configured timeout is not a
wall-clock deadline for the entire `up` command. A timeout, unhealthy
workload, invalid certificate, routing failure, or unexpected response fails
the revision and enters rollback.

The protocol deadline surrounding a scalable call is derived from the exact
locked action/selection count: each work unit receives one bounded command
phase plus one bounded readiness phase, followed by one fixed coordination
margin. The calculation saturates at a 24-hour hard ceiling. Project-wide
provider inspection uses that ceiling because the remote resource count is
unknown until the result arrives. Plugins must represent sequential mutation
work as plan actions rather than hiding an action-count multiplier inside one
unit.

## 10. Failure and rollback architecture

Every applied action records:

- stable action ID;
- owning capability/plugin and exact plan identity;
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

If a successful apply result arrives concurrently with cancellation, core
first persists its exact post-apply state and action journal, then treats the
operation as cancelled and enters normal rollback. It never commits that
revision as a success.

Initial deployment rollback destroys capabilities that were absent before the
operation, in reverse apply order. When an apply call returned rediscovery
state, core supplies that post-apply state to whole-capability cleanup; a call
that failed before returning state falls back to the locked prior observation,
so the plugin must use the locked context and exact deterministic resource
identities to rediscover only its partial work. Update rollback instead
receives the locked pre-apply state and restores and reapplies the previous
generated Compose base and runtime override where possible. Previously loaded
built images remain in the remote Docker cache. The temporary
application-environment override is not retained; rollback can re-render
currently resolvable references, but it cannot recover historical secret
values or environment values that have since changed. Mutable external image
tags are likewise outside the guarantee. Cleanup continues after individual
compensation failures and reports the failures.

Provider-native plugins compensate exact applied actions where supported.
This is not a promise that every provider-native update restores a previous
revision: core invokes only rollback metadata explicitly advertised by the
locked plan and reports unsupported or failed compensation for recovery.
Potentially executed existing Target or Runtime actions with no declared
rollback contract are also reported as incomplete; they are not silently
classified as reversible.

Fly initial creation records provisional App, Machine, and volume IDs for
exact whole-target cleanup. Exposure rollback releases the exact shared IPv4
allocated by the failed operation before target cleanup removes the App.

OCI images pushed for Kubernetes/Fly remain in the registry after rollback or
environment destruction because they are build artifacts/cache rather than
runtime resources.

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

Kubernetes serializes every mutation for one immutable project through one
project Lease in the configured existing control namespace. Acquisition and
stale-owner takeover use Kubernetes `resourceVersion` continuity; a live owner
heartbeats, same-owner reacquisition returns the same token, and release or
lease expiry ends the authority. Every owned environment namespace records
that control namespace; changing the setting while it exists fails before
mutation so a different Lease cannot silently replace the original authority.
Initial namespace ownership uses an atomic create. `AlreadyExists` and
lost-response recovery continue only after exact ownership, control-namespace,
and planned spec-hash reinspection, never by server-side applying over a
competing authority.

Fly deliberately serializes all mutations for one immutable project. A
deterministic provider-visible lock App contains a stopped sentinel Machine
whose Fly Machine lease is the authority. The lock App is shared control
state, remains after environment teardown, and is not replaced by a
process-local mutex. `lock_ttl_seconds` bounds stale lease recovery.

Core requests project scope for every mutation on an Environment-isolated
profile. This safe initial contract serializes branches that share one
Kubernetes/Fly project authority while their runtime resources remain
environment-isolated.

The default acquisition timeout is 30 seconds. Read-only operations need no
lock. `down --force` may bypass the lock only for machine isolation when the
remote lock authority returns `unavailable`; it still requires explicit user
confirmation. It never bypasses a busy/held lock, and a shared generic SSH
host or Environment-isolated provider never uses this bypass.

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

Human mutations render the authoritative plan before applying it. JSON/plain
real mutations keep stdout to one final result; automation reviews the
corresponding single-document `--dry-run` first. The locked plan remains
authoritative internally and is journaled even when it is not emitted twice.

Environment isolation treats one Kubernetes namespace or one exact Fly
resource aggregate as the deletion boundary. Kubernetes retains the cluster,
nodes, control namespace, ingress/certificate components, and registry. Fly
retains its shared lock App. Both retain pushed registry images as build
cache. Kubernetes deletes the namespace's PVC objects (the StorageClass/PV
reclaim policy remains cluster-owned); Fly deletes the selected environment's
owned volumes.

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

`prune` is an explicit, capability-gated selected-destroy path for expired
Environment-isolated Kubernetes/Fly resources. Core accepts only
environment-contract version 1 observations with exact project ownership,
unique environment IDs, and provider expiry metadata. It snapshots entries
expired at a captured time, renders the exact plan for human output or
`--dry-run`, confirms, acquires the project lock, and rejects any candidate-set
or complete canonical plan-digest drift on reinspection. The provider receives
selection schema 1, reason `expired`, and only those environment IDs. Missing
`dev.lightrail.selected-destroy.v1` support fails closed; there is no fallback
to `down --all` and no background cleanup controller.

## 13. Security boundaries

The security model is explicit:

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
- Kubernetes always addresses the explicit context, never guesses an
  IngressClass, rejects a literal or resolved loopback API host, and limits
  deletion to exact owned namespaces. Shared cluster components are not an
  environment resource.
- Fly credentials arrive only through typed secret input. Destruction checks
  Machine ownership metadata before deleting a normal App and never treats a
  same-named App alone as sufficient proof. A zero-Machine interrupted-create
  orphan additionally requires the project marker, deterministic
  project-network prefix, and exact captured App/network/volume continuity.
- Secret wrapper diagnostics are redacted, and bundled plugins must keep
  plaintext out of logs, plans, errors, journals, and JSON output.
- Provider/runtime labels are ownership evidence, but destructive operations
  must also constrain queries to the selected target/account and project ID.

## 14. Deferred extension points

The following capabilities are not implemented. Their intended attachment
points are:

| Future feature | Extension point |
| --- | --- |
| Kubernetes/k3s cluster provisioning | target/setup plugin |
| shared ingress/certificate/RBAC setup | target/setup plugin |
| authenticated private access | exposure/tunnel plugin |
| GitHub/GitLab PR automation | source/event plugin |
| usage and cost reports | observation/usage plugin |
| background expiry controller | scheduler/state extension |
| user-selectable blue/green/canary rollouts | runtime strategy capability |
| remote state | state backend plugin |
| custom DNS | DNS plugin outside MVP policy |

The core continues to own identity, orchestration, trust checks, typed secret
transport, and user-facing command behavior. A future implementation must not
move those invariants into one provider plugin or introduce a mandatory
control plane.
