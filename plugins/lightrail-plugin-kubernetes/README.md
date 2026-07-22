# Lightrail Kubernetes plugin

This executable plugin deploys the current Lightrail worktree to an existing
Kubernetes cluster without a remote Lightrail agent. It translates resolved
Compose input into native Kubernetes resources, builds local sources with
Docker Buildx, pushes immutable revision images, and operates the cluster
through an explicitly selected `kubectl` context.

This file is a local orientation guide. The repository `README.md`,
`docs/product-spec.md`, `docs/architecture.md`, and
`docs/plugin-protocol.md` remain the authoritative product contract.

## Scope and boundaries

The plugin never creates, resizes, or deletes clusters or nodes. It also never
installs or updates shared RBAC, the control namespace, an ingress controller,
an `IngressClass`, cert-manager, a `ClusterIssuer`, a registry, or storage
infrastructure.

It serves the `builder`, `target`, `runtime`, `exposure`, `dns`, and
`operation-lock` capabilities. Core remains responsible for Git and
environment identity, lifecycle ordering, plans, journals, rollback
coordination, and user confirmation.

Plugin stdout is reserved for newline-delimited JSON-RPC. Diagnostics belong
on stderr. Subprocesses are bounded and cancellable, and secret values must
never enter plans, journals, arguments, or diagnostics.

## Module map

| File | Responsibility |
| --- | --- |
| `src/main.rs` | Executable entry point and protocol serving |
| `src/lib.rs` | Stable plugin ID and public exports |
| `src/config.rs` | Settings defaults, parsing, and fail-fast validation |
| `src/command.rs` | Bounded, cancellable `kubectl` and Docker execution |
| `src/model.rs` | Desired-state parsing, Compose translation, builds, manifests, names, and URLs |
| `src/lock.rs` | Project-scoped Kubernetes Lease authority and heartbeat |
| `src/plugin.rs` | Capability dispatch, inspect/plan/apply, readiness, rollback, destroy, and logs |

## Capability ownership

| Capability | Behavior and ownership |
| --- | --- |
| `target` | Preflights the selected remote context, control namespace, schedulable node platforms, exact ingress `LoadBalancer` Service, ingress contract, public ingress address, and HTTP-01 issuer. It owns no cluster infrastructure, so target teardown retains the cluster and shared controllers. |
| `builder` | Builds locally and pushes revision-addressed OCI images. Registry images are retained during teardown; registry garbage collection is external. |
| `runtime` | Owns one namespace per environment and the managed workloads, Services, Secrets, and PVCs inside it. Every non-Job service receives private cluster DNS; a portless service uses a selector-backed headless Service without a guessed port. It waits for Jobs and workload rollouts concurrently under one phase deadline. Namespace deletion is the environment teardown boundary. |
| `exposure` | Owns only the environment's Ingresses and, for Traefik, redirect Middleware. Only selected apps are public; other Services remain private. HTTP redirects to trusted HTTPS, and readiness probes each app's configured health contract. |
| `dns` | Calls no DNS provider. It produces IP-derived `sslip.io` or `nip.io` URLs and refreshes namespace expiry metadata after a successful deployment. |
| `operation-lock` | Uses one authoritative Kubernetes Lease per project to serialize mutations across every environment in that project. |

Public URLs have the form
`https://<branch>.<app>.<profile>.<project>.<8-hex-ip>.{sslip.io,nip.io}`.
The branch segment comes before the app segment. A public ingress IPv4 is
required; localhost and loopback targets fail preflight before mutation.

## Mutation safety

### Lock

- Only project-scoped mutation locks are supported. The deterministic Lease
  lives in the existing `control_namespace` and is retained after release.
- The Lease records an operation-token digest and exact scope metadata, never
  the token itself. Acquisition honors the requested timeout.
- A bounded heartbeat renews the Lease faster than its expiry. Loss of
  authority cancels the active operation, and every mutation phase reasserts
  live authority, including immediately before a successful return.
- Every owned environment Namespace records its `control_namespace`.
  Changing that setting while the environment exists fails closed before
  mutation, so an operation cannot acquire a different Lease and silently
  change the original lock authority.
- Initial Namespace ownership is claimed with an atomic create. A concurrent
  `AlreadyExists` or lost-response path continues only after exact ownership,
  control namespace, and planned spec-hash reinspection; it never
  server-side-applies over a competing authority.
- Release performs a compare-and-swap replacement at the exact
  `resourceVersion`, leaving a vacant expired Lease. It does not use a
  check-then-delete race. If a locally held Lease has disappeared, release
  reports lost authority rather than treating absence as success.
- There is no lock bypass. Kubernetes does not support `down --force`.

### Rollback

- Apply journals carry the exact rollback metadata produced by the plan.
  Both `Started` and `Succeeded` mutation records are rollback candidates and
  are checked against live ownership and revision continuity.
- Runtime object mutations are explicitly marked as unsupported for automatic
  exact rollback. Kubernetes rollout history and a prior spec hash cannot
  restore the full prior object, while retaining arbitrary live workload
  manifests could persist admission- or user-injected secret material. Core
  therefore reports rollback as incomplete instead of accepting a
  metadata-only approximation.
- Exposure rollback stores sanitized prior Ingress and Middleware manifests.
  It restores those exact manifests or deletes only resources created by the
  failed attempt. Application secret values are never part of that metadata.
- DNS rollback compares the prior and attempted expiry values before restoring
  the exact prior value.
- A failed initial deployment can deterministically remove its owned
  namespace even when no pre-apply inspection existed. Rollback never widens
  ownership or restores application data, PVC contents, or secret history.

### Destroy and prune

- Ownership labels, not names alone, authorize deletion. Normal teardown uses
  only the exact namespace/environment set captured by the locked `current`
  inspection; it never re-lists and silently widens the confirmed deletion.
- Immediately before deletion, the plugin reinspects exact management,
  project, environment, and namespace identity. Resources that do not match
  remain untouched and are reported.
- An owned but empty namespace is still deleted. An absent environment is an
  idempotent no-op. Prune deletes only the exact selected environment IDs from
  the locked inspection.
- Runtime namespace deletion aggregates environment-owned exposure and DNS
  cleanup. The cluster, nodes, control namespace, shared ingress and
  cert-manager components, storage infrastructure, operation Lease, and
  pushed images are retained.

## Configuration

These settings are merged from the capability configuration served by this
plugin:

| Setting | Required/default | Notes |
| --- | --- | --- |
| `context` | required | Existing kubeconfig context, always passed explicitly |
| `kubeconfig` | omitted | Optional absolute kubeconfig path |
| `registry` | required | Non-loopback OCI registry host without a URL scheme |
| `repository` | required | Lowercase repository prefix beneath the registry |
| `ingress_class` | required | Exact existing Kubernetes `IngressClass` |
| `ingress_service_namespace` | required | Namespace of the exact existing ingress-controller `LoadBalancer` Service |
| `ingress_service_name` | required | Name of the exact existing ingress-controller `LoadBalancer` Service |
| `cluster_issuer` | required | Existing Ready cert-manager `ClusterIssuer` with an HTTP-01 solver |
| `traefik_http_entrypoint` | `web` | Existing Traefik entrypoint for redirect-only HTTP Ingresses |
| `traefik_https_entrypoint` | `websecure` | Existing Traefik entrypoint for public TLS Ingresses; must differ from the HTTP entrypoint |
| `namespace_prefix` | `lr` | Prefix for environment-owned namespaces |
| `control_namespace` | `lightrail-system` | Existing namespace holding project Lease locks |
| `dns_domain` | `sslip.io` | Must be exactly `sslip.io` or `nip.io` |
| `image_pull_secret` | omitted | Optional Secret name made available in each environment namespace by cluster policy |
| `platforms` | `[]` | Empty discovers schedulable Linux node architectures; explicit values must be a subset observed on Ready schedulable nodes and constrain Pods with an architecture selector or required affinity |
| `replicas` | `1` | Ordinary workload replicas, from 1 through 100 |
| `ttl_hours` | `72` | Expiry metadata refreshed by `up`; cleanup remains explicit |
| `command_timeout_seconds` | `300` | Bound for one Docker or `kubectl` subprocess |
| `readiness_timeout_seconds` | `300` | Overall bound for the concurrent rollout/Job phase and for endpoint readiness |

Unknown setting names fail validation. This keeps profile typos from being
silently ignored.

The operator machine needs `kubectl`, Docker Buildx, registry push
authentication, and network access to the selected API server and public
endpoints. The cluster needs:

- an existing non-loopback context and sufficient RBAC for namespaces,
  workloads, networking resources, and Leases in the control namespace;
- nodes compatible with the selected or discovered image platforms;
- pull access to the registry; the plugin references but never copies an
  `image_pull_secret`;
- a configured, exact existing `LoadBalancer` Service with a public ingress
  IPv4, and an `IngressClass` whose controller is exactly
  `k8s.io/ingress-nginx` or `traefik.io/ingress-controller`;
- a Ready cert-manager `ClusterIssuer` configured for HTTP-01;
- for Traefik, the current or legacy Middleware CRD and the configured
  `web`/`websecure` entrypoints (or their configured replacements);
- suitable storage policy and classes for any requested PVCs.

## Known limitations

- Compose translation is intentionally strict. Host networking, privileged
  containers, bind mounts, Compose configs/secrets, and unsupported advanced
  Buildx inputs fail validation. Every service needs `image:` or `build:`.
  Non-empty service fields outside the translated allowlist fail rather than
  being silently dropped.
- Only Compose's normalized implicit `default` network is accepted. Custom,
  external, multiple, aliased, statically addressed, driver-configured, or
  optioned networks fail validation. Named volumes must use ordinary
  environment-owned generated names; external volumes, custom names, drivers,
  and driver options are rejected. Non-empty top-level Compose config or
  secret declarations are also unsupported.
- The operation context's granted Git root is the sole local source authority.
  Build contexts and explicit Dockerfiles must exist, resolve within it after
  symbolic-link resolution, and are normalized to project-relative paths for
  canonical revision input. Directory-derived Compose project,
  default-network, and named-volume names therefore do not affect that input.
  Every local-build revision is nevertheless operation-scoped because Git
  cannot prove that ignored files are absent from Docker's context; Buildx
  continues to reuse content-addressed layers.
- Jobs cannot back public apps. Shared ReadWriteOnce named volumes cannot be
  combined with more than one replica. Completed image-only Jobs are retained
  until environment teardown, so an unchanged repeated `up` is idempotent;
  Lightrail does not attach a Job TTL. Because every local build uses an
  operation-scoped revision, an existing local-build Job intentionally
  requires `down` then `up` on every later deployment until
  content-addressed build-context revisions exist.
- Long-running workloads backed by generated environment Secrets receive a
  non-secret operation-derived Pod-template revision. This intentionally
  rolls those Pods once per `up` operation, ensuring changed environment or
  secret values take effect without hashing or retaining secret plaintext.
- Removing owned runtime or exposure resources, adding resources to an
  established runtime topology, or changing an existing Job fails closed and
  requires `down` followed by `up`. Adding exposure resources is supported:
  exact compensation metadata lets rollback delete only resources added by a
  failed attempt.
- Namespace deletion during `down` or `prune` declares an explicitly
  unsupported inverse: deleted workloads, Secrets, PVC objects, and
  application data cannot be reconstructed exactly.
- Only the community ingress-nginx and Traefik controller contracts above are
  implemented. Custom DNS, provider-native hostnames, IPv6-only ingress, and
  arbitrary TCP/UDP exposure are deferred.
- Logs are bounded historical reads; follow mode, tunnels, remote exec, usage
  reporting, cluster provisioning, and a background expiry janitor are
  deferred.

## Local validation

Run the focused package checks without provider credentials:

```console
cargo test -p lightrail-plugin-kubernetes --locked
cargo clippy -p lightrail-plugin-kubernetes --all-targets --locked -- -D warnings
```

> Do not run a live cluster test without explicit authorization. Automated
> tests must not contact or mutate a real provider. Any authorized live test
> must use a fresh fixture and unique project ID, run `doctor --target` and
> `up --dry-run` first, and finish with confirmed cleanup and an independent
> ownership check.
