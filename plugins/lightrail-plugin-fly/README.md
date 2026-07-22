# Lightrail Fly.io plugin

This executable plugin deploys to Fly Apps and Machines without a remote
Lightrail agent. It builds the current worktree locally with Docker Buildx,
pushes revision-tagged images to `registry.fly.io`, and uses provider-native
`https://<app>.fly.dev` endpoints.

Each Compose service becomes one Fly App and one Machine. All Apps in one
Lightrail environment join the same deterministic custom 6PN; another preview
uses another 6PN. Only selected public apps receive Fly services and a shared
IPv4. Readiness requires trusted HTTPS at the configured health path and a
working HTTP-to-HTTPS redirect.

Mutation locking is project-wide. A deterministic lock App contains one
stopped sentinel Machine, and a Fly Machine lease on that sentinel serializes
all Lightrail environments for the project. This is intentionally stronger
than an environment-only lock. Long operations refresh the same lease with its
nonce before the remaining TTL becomes unsafe; every bounded mutation phase
reserves provider-call and rollback margins. The lock App is shared
infrastructure and is retained when environments are destroyed.

Tokens are received only through protocol stdin. Registry authentication uses
Docker's password stdin with an operation-scoped Docker configuration
directory; tokens never appear in process arguments, plans, journals, or
metadata.

Current intentional limits:

- one named volume per service/Machine;
- resolved Compose may use only its normalized implicit `default` network
  (`<compose-project>_default`, empty IPAM, and `default: null` service
  membership). Custom/multiple/external networks, aliases, static addresses,
  and network options fail closed because Fly replaces that topology with the
  environment's custom 6PN;
- named volumes must retain Compose's generated
  `<compose-project>_<volume-key>` name. External or custom/shared names and
  driver options fail closed;
- changing services, volume topology, or `volume_size_gb` requires `down`
  followed by `up`;
- Compose `healthcheck` is accepted as source metadata and contributes to the
  revision, but it is not copied into the Machine. Public Fly checks and CLI
  readiness use the Lightrail app `health_path`, `health_status`,
  `health_interval_seconds`, and `health_timeout_seconds` contract;
- Compose secrets, configs, env files, privileged services, bind mounts,
  non-empty service labels/extensions, and replica counts other than one fail
  validation;
- every local build context and Dockerfile is canonicalized and must remain
  inside the operation context's exact Git project root, including through
  symlinks;
- clean external-image revisions are portable across equivalent checkout
  roots. Local builds are operation-scoped because ignored Docker-visible
  bytes are not proven by Git. Resolved service/app-environment plaintext is
  never hashed into provider-visible revision metadata; environments with
  resolved values are also operation-scoped;
- app secret references are not implemented and fail closed rather than
  placing values in provider-readable Machine `config.env`;
- non-empty `x-lightrail` workload kinds fail closed; Jobs and stateful
  workload semantics are not silently converted into always-restart services;
- private dependencies are reported as `<fly-app>.internal`; the plugin does
  not synthesize Compose service-name DNS aliases, and workloads must listen on
  Fly 6PN for direct private traffic;
- `auto_stop`/autostart is configured through Fly Proxy only for public Apps.
  Private Apps have no public service wake trigger and run their Machine with
  the always-restart policy. Inspection degrades stopped private Machines and
  stopped public Machines when Proxy autostart is disabled;
- external image tags are passed through as configured; only locally built
  images are resolved to an immutable digest before Machine update;
- previous-revision runtime rollback is not implemented, so an existing
  environment update failure is reported as rollback-incomplete;
- public App inspection probes all selected Apps concurrently under one shared,
  cancelable readiness deadline. Mixed workload revisions or member expiry
  values degrade the environment rather than presenting a Ready or
  prune-eligible aggregate;
- the expiry deadline is committed through Fly's single-key Machine metadata
  API only in the final DNS capability after Runtime and Exposure succeed.
  Runtime preserves the prior successful expiry, and a failed final commit
  restores each exact prior optional value;
- `lock_ttl_seconds` must be more than 180 seconds greater than the larger of
  `command_timeout_seconds` and `readiness_timeout_seconds`;
- shared IPv4 allocation and exact release use Fly's GraphQL
  `allocateIpAddress`/`releaseIpAddress` mutations (`shared_v4`, then exact App
  ID and address). Fly does not currently provide these operations in its
  stable public Machines API, and its GraphQL API is not stability-guaranteed;
  compatibility tests pin the current flyctl request and response shapes;
- teardown and rollback attempt every independently captured App/address,
  journal each result, and report all remaining exact resources instead of
  stopping at the first provider failure;
- historical/follow logs and tunnels are deferred.
