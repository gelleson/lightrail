# Lightrail plugin protocol

Status: protocol 1.0.0 is implemented by
`lightrail-plugin-protocol`, the core plugin host, and the three bundled
plugins.

This document describes the language-neutral process boundary. The Rust crate
provides a client, server, typed messages, and a `PluginHandler` convenience
trait, but another language can implement the same JSON wire contract.

## 1. Process and framing

Core starts one plugin executable for a command session:

- stdin carries JSON-RPC 2.0 requests and notifications from core;
- stdout carries JSON-RPC 2.0 responses and notifications from the plugin;
- stderr carries human diagnostics and is never protocol data.

Each message is one compact UTF-8 JSON object followed by `\n`. Literal
newlines inside strings must be JSON escaped. The maximum encoded message size
is 16 MiB. An empty line, banner, log line, malformed object, unknown response
ID, or plugin-to-core request on stdout is a protocol error.

Handlers may run concurrently. Writers must serialize each complete JSON line
atomically. Core uses numeric request IDs; implementations must accept string
or integer IDs.

Core clears the inherited child environment and passes an explicit allowlist.
The bundled plugins receive the paths and Docker/SSH integration variables
they need, but not `LIGHTRAIL_SECRET_*` values. Secrets travel only in typed
request bodies on stdin.

The normal shutdown request is `plugin.shutdown` with `{}` parameters. Core
then closes stdin and waits up to five seconds before killing an unresponsive
child. The default operation request timeout is 30 minutes.

## 2. Trust, discovery, and pins

Plugins are trusted native executables running with the invoking user's
permissions. Protocol boundaries and checksums provide compatibility and
integrity; they are not a sandbox.

The bundled IDs are:

| ID | Capabilities |
| --- | --- |
| `dev.lightrail.compose` | `source`, `builder`, `runtime`, `exposure`, `dns` |
| `dev.lightrail.ssh` | `target`, `operation-lock` |
| `dev.lightrail.hetzner` | `target`, `operation-lock` |

Core locates bundled executables beside `lightrail` and checks their manifest
ID and package version. The resolved path is canonical and absolute; a
missing sibling fails closed instead of searching `PATH`. Debug source builds
may additionally use the explicit workspace `target/debug` path. Bundled
entries are not required in `lightrail.lock`.

Third-party plugins must be installed explicitly from a local executable or
HTTPS URL. Their committed lock shape is:

```toml
schema = 1

[[plugins]]
id = "example.target"
version = "1.2.3"
protocol = "1.0.0"
source = "https://example.invalid/example-target"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Plugin commands run inside an initialized Lightrail project and update that
project's `lightrail.lock`. `plugin install` probes the manifest, installs the
executable, and adds the pin. `plugin sync` installs existing pins; `plugin
update` reprobes the pinned source; `plugin remove` removes the pin and
installed version. Deployment never downloads a missing third-party plugin
automatically.

Before launch, core checks the source policy, basic lock structure, installed
SHA-256 digest, handshake ID/version, negotiated protocol compatibility, and
selected capabilities. The lock's `protocol` field is parsed as a canonical
version and compared exactly with the executable manifest's emitted protocol
version during launch, in addition to live compatibility negotiation.

## 3. Version negotiation and manifest

The first request is `plugin.initialize`:

```json
{"jsonrpc":"2.0","id":1,"method":"plugin.initialize","params":{"core_version":"0.1.0","protocol_version":"1.0.0","supported_protocol_versions":["1.0.0"]}}
```

A successful Compose plugin response has this shape, abbreviated only inside
the JSON Schema:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocol_version":"1.0.0","session_id":"018f6fa7-8ec2-7a39-b899-725959e23d8a","manifest":{"id":"dev.lightrail.compose","name":"Lightrail Compose","version":"0.1.0","protocol":{"version":"1.0.0","requires":{"minimum":"1.0.0","maximum_exclusive":"2.0.0"}},"executable":{"command":"lightrail-plugin-compose","homepage":"https://github.com/gelleson/lightrail"},"capabilities":["source","builder","runtime","exposure","dns"],"required_secrets":[{"name":"*","description":"Only app environment secret names explicitly referenced by lightrail.toml","required":false}],"config_schema":{"type":"object","properties":{}},"config_ui_hints":{}}}}
```

Protocol versions are canonical `major.minor.patch` strings. The manifest
declares both the exact emitted version and the half-open range of core
versions it accepts. Core rejects an unoffered selection, a mismatched manifest
version, a different plugin ID or pinned semantic version, or a missing
capability.

Capabilities are stable strings. Protocol 1.0.0 knows `source`, `builder`,
`target`, `runtime`, `exposure`, `dns`, `secrets`, `operation-lock`, and
`usage`; namespaced unknown strings remain representable for extensions.
Representability does not mean the CLI implements a corresponding command.

## 4. Methods

The implemented method names are:

| Method | Parameters | Result |
| --- | --- | --- |
| `plugin.initialize` | `InitializeRequest` | `InitializeResult` |
| `plugin.validate` | `ValidateRequest` | `ValidateResult` |
| `plugin.inspect` | `InspectRequest` | `InspectResult` |
| `plugin.plan` | `PlanRequest` | `PlanResult` |
| `plugin.apply` | `ApplyRequest` | `ApplyResult` |
| `plugin.destroy` | `DestroyRequest` | `DestroyResult` |
| `plugin.cancel` | `CancelRequest` | `CancelResult` |
| `plugin.lock.acquire` | `LockAcquireRequest` | `LockAcquireResult` |
| `plugin.lock.release` | `LockReleaseRequest` | `LockReleaseResult` |
| `plugin.logs` | `LogsRequest` | `LogsResult` |
| `plugin.shutdown` | `{}` | `{}` |

Plugins send structured notifications with `plugin.event`. Core may also send
the standard `$/cancelRequest` notification for one timed-out JSON-RPC request.

## 5. Operation context

Validate, inspect, plan, apply, destroy, and logs carry an
`OperationContext`:

```json
{
  "operation_id": "018f6fa9-1071-7d75-9cf8-eec326a7088e",
  "environment_id": "lr-58ce76e3c31e120f98bb2140",
  "profile": "preview",
  "project_root": "/workspace/myproject",
  "config": {
    "host": "server.example.com",
    "public_ipv4": "1.2.3.4"
  },
  "secrets": {},
  "metadata": {
    "capability": "target",
    "operation": "up",
    "all": false,
    "project_id": "018f6f9f-21aa-7da8-a1b2-31da91ed5148",
    "project_slug": "myproject",
    "labels": {
      "lightrail-managed": "true",
      "lightrail-environment-id": "lr-58ce76e3c31e120f98bb2140"
    },
    "target": {}
  }
}
```

`config` is the merged opaque settings for the capability slots served by that
same plugin. `metadata.target` carries the target plugin's observed/applied
transport state to downstream capabilities. `project_root` is explicitly
granted local input; a plugin must not assume that unrelated filesystem paths
or ambient environment variables are available. Application secret references
are resolved only as part of runtime `up`; that context is retained for a
possible runtime rollback within the same operation. Newly constructed
non-`up` contexts still receive an explicitly declared credential when that
plugin needs it, such as the Hetzner API token used for provider inspection or
deletion.

The environment ID is stable for project UUID, selected profile, and raw
current branch. Commit and dirty state affect deployment revision rather than
environment identity.

## 6. Validation, inspection, and planning

`plugin.validate` receives context plus the desired state:

```json
{"jsonrpc":"2.0","id":2,"method":"plugin.validate","params":{"context":{"operation_id":"...","environment_id":"lr-...","profile":"preview","config":{},"secrets":{},"metadata":{}},"desired":{"schema":1}}}
```

It returns `valid`, structured `diagnostics`, and optional
`normalized_config`. Validation must not mutate remote state.

`plugin.inspect` receives only context and returns:

```json
{"status":"ready","endpoints":[{"app":"api","url":"https://feature-login.api.preview.myproject.01020304.sslip.io"}],"state":{"revision":"sha256:..."},"diagnostics":[]}
```

Status is one of `absent`, `pending`, `ready`, `degraded`, `destroying`, or
`unknown`. `state` is plugin-owned rediscovery data. Inspection is read-only.
For project-wide inspection, bundled plugins expose
`state.environments` entries with an environment ID, optional branch/profile,
status, and endpoints. Machine target inspection also exposes `state.targets`;
core fans out downstream inspection across those target states and preserves
an endpoint-free degraded environment summary when one machine is
unreachable.

`plugin.plan` receives context, desired state, and optional current state. Its
result contains:

- a stable `plan_id`;
- `has_changes`;
- ordered actions with stable IDs, kinds, summaries, destructive flags,
  dependencies, and optional rollback metadata; and
- non-secret plugin metadata needed to reject a stale or modified apply.

Planning is side-effect free. Core refuses a destructive action returned by an
`up` plan; destructive work belongs to `down`.

## 7. Apply, journal, and rollback metadata

`plugin.apply` receives the exact complete `PlanResult`, not only a plan ID,
plus any existing action journal:

```json
{"jsonrpc":"2.0","id":4,"method":"plugin.apply","params":{"context":{"operation_id":"...","environment_id":"lr-...","profile":"preview","config":{},"secrets":{},"metadata":{}},"plan":{"plan_id":"plan-b14f","actions":[],"has_changes":false,"metadata":{}},"journal":[]}}
```

Plugins validate the plan ID against its actions and metadata before mutation.
The result contains an optional revision, rediscoverable state, and a final
journal snapshot.

Each `ActionJournalEntry` has a monotonically increasing sequence number,
action ID, status, optional safe message, optional rollback metadata, and
non-secret metadata. Status values are `started`, `succeeded`, `failed`,
`rolling_back`, `rolled_back`, `rollback_failed`, and `skipped`.

Rollback metadata contains a support flag, optional inverse action, an opaque
redacted token, and non-secret parameters. It describes infrastructure
compensation, not rollback of database writes, volumes, external side effects,
or unavailable historical secrets.

`plugin.destroy` receives context, optional inspected current state, a `force`
boolean, and a journal. It returns `destroyed`, the final journal, and every
remaining resource identifier. Already-absent is success. `force` is an
explicit recovery signal; it does not remove the requirement for core-side
destructive confirmation or ownership checks.

## 8. Secrets and wildcard declarations

`PluginManifest.required_secrets` is a list of:

```json
{"name":"hetzner-token","description":"Hetzner Cloud API token","required":true}
```

For an ordinary declaration, core permits only the listed logical names. If
selected configuration references another secret, core rejects the operation
instead of sending it.

A requirement whose name is `"*"` has deliberately narrow semantics:

1. Core scans the selected capability's configuration for explicit
   `{"secret":"name"}` references.
2. For a runtime `up`, it also scans the desired app environment assembled
   from app, profile, and per-app overrides.
3. Core resolves and sends only those referenced names.
4. It never enumerates or forwards all keyring entries.

The bundled Compose plugin declares `"*"` with `required: false`, then receives
only application values actually referenced by an `up` deployment. Status,
URLs, logs, and a standalone `down` neither resolve nor transmit app secrets;
a rollback within that `up` may reuse its already resolved runtime context.
Core does not treat the wildcard itself as a secret name or lookup; each
concrete name discovered beneath it is treated as required. The wildcard
declaration's `required` flag therefore does not make an absent, unreferenced
value fail.

The Hetzner plugin declares exactly one required name, `hetzner-token`. The SSH
plugin declares none and relies on OpenSSH configuration, an optional absolute
identity-file path, or the forwarded SSH agent socket.

Secret values are JSON strings inside `context.secrets`. Rust's `SecretValue`
redacts `Debug` and `Display`, but all plugin implementations must also avoid
echoing payloads, errors, or stderr. Values must not appear in plans, journals,
observations, provider labels, or manifests.

## 9. Events and logs

Plugins emit notifications such as:

```json
{"jsonrpc":"2.0","method":"plugin.event","params":{"kind":"progress","operation_id":"018f6fa9-1071-7d75-9cf8-eec326a7088e","message":"Building target-platform images with Buildx"}}
```

Event kinds are:

- `progress`, with operation ID, safe message, and optional counts;
- `journal`, with operation ID and one action entry;
- `diagnostic`, with optional operation ID and one structured diagnostic; and
- `log`, with stream ID and one log record.

`plugin.logs` returns historical records and an optional stream ID. When
`follow` is true, subsequent records arrive as `log` events. The event channel
is intentionally lossy; authoritative state must always be recoverable through
inspection.

## 10. Locks and cancellation

Target plugins advertise `operation-lock` and implement explicit acquire and
release:

```json
{"jsonrpc":"2.0","id":8,"method":"plugin.lock.acquire","params":{"environment_id":"lr-...","scope":"target","scope_id":"target:dev.lightrail.ssh","operation_id":"018f6fa9-1071-7d75-9cf8-eec326a7088e","timeout_ms":30000}}
```

A successful result includes `acquired: true` and an opaque release token.
Failure may include the current holder. Release carries the same environment
ID, scope, scope ID, and operation ID plus that token; already released is
successful. Reacquiring the same owner is idempotent only while its lock
authority is still alive and returns the same token. Core performs this check
immediately before each apply or destroy request. It aborts on an unacquired,
tokenless, or different-token response and releases a newly returned
different token.

`LockScope` has three wire values:

- `environment`, for one deterministic branch/profile environment;
- `project`, for all environments selected by one immutable project ID; and
- `target`, for shared resources on a target such as host-wide Traefik.

Generic SSH uses target scope and atomically creates the host-wide
`/tmp/lightrail-host.operation.lock` directory with POSIX `mkdir`. The remote
shell keeps stdin open for the lock lifetime and removes the directory when
the session ends; no remote `flock` command is required. Hetzner uses
environment scope for one machine and project scope for `--all`, snapshots
the exact provider resources in that scope, and holds remote `flock`
processes on every reachable selected machine. A first provision upgrades its
session reservation to a remote lock on the new machine after bootstrap;
project scope acquires the per-machine locks in deterministic provider-ID
order. It rechecks immutable provider IDs and labels before destructive
mutation.

Core may honor `down --force` without a token only for a machine-isolated
provider whose remote lock authority returns `unavailable`. It never bypasses
an `acquired: false`/busy lock, and it does not enable this bypass for a shared
generic SSH target.

There are two cancellation mechanisms:

- `plugin.cancel` addresses a logical operation ID and returns whether the
  plugin acknowledged it.
- `$/cancelRequest` addresses a JSON-RPC request ID. The Rust server aborts
  that handler future; the client sends it after a request timeout.

Child processes used by the bundled plugins are kill-on-drop. Followed logs
stop on Ctrl+C. During `up` and `down`, Ctrl+C sends `plugin.cancel`, waits for
the active plugin's safe stopping point, and then enters the orchestrator's
normal rollback or orderly-stop path.

## 11. Errors and compatibility

Plugin application failures use JSON-RPC code `-32000`; the `data` field is a
structured `PluginError`:

```json
{"jsonrpc":"2.0","id":4,"error":{"code":-32000,"message":"SSH connection timed out","data":{"kind":"timeout","code":"ssh_timeout","message":"SSH connection timed out","retryable":true,"retry_after_ms":1000}}}
```

Kinds are `validation`, `unsupported`, `authentication`, `not_found`,
`conflict`, `lock_unavailable`, `timeout`, `rate_limited`, `unavailable`,
`cancelled`, and `internal`. Only errors with `retryable: true`, client I/O
errors, and request timeouts are eligible for bounded core retry. Eligibility
does not mean every method is repeated: core avoids blindly retrying a
mutation or lock acquisition after an ambiguous outcome. `details` must
contain no secret values.

The server also uses standard JSON-RPC errors for parse, invalid request,
method-not-found, and invalid-parameters failures. Unknown optional fields are
accepted for forward compatibility. A breaking wire or semantic change
requires a new protocol major version.

Usage reporting is only a representable capability string. There is no usage
command or bundled usage plugin. Authenticated tunnels, Fly.io, Kubernetes,
k3s, PR event sources, and remote state plugins are likewise not implemented.
