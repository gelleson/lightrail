# Lightrail Hetzner plugin

`lightrail-plugin-hetzner` is the bundled, agentless Hetzner Cloud target. It
speaks Lightrail's newline-delimited JSON-RPC protocol over stdin/stdout and
uses the official Hetzner Cloud HTTP API plus the local OpenSSH client.

It owns only resources carrying all of its immutable management, project, and
environment labels. Server and firewall names are deterministic, but labels
are the authority for inspect and destroy. The API token is accepted only as
the declared `hetzner-token` protocol secret and is sent only in the HTTP
`Authorization` header.

## Lock semantics

Core must inspect a scope through the same plugin process before acquiring its
mutation lock. An environment lock keeps both its environment and project
`flock` sessions open on the machine. A project lock snapshots every
project-labelled server and firewall, acquires a project `flock` on every
reachable server, then re-lists and compares exact provider IDs before any
deletion. Scope-aware in-process reservations prevent overlapping environment,
project, and target mutations in the plugin session.

Before the first server exists, no remote lock authority is possible: the
plugin reserves the deterministic environment in its process, lists by
immutable labels immediately before creation, and relies on Hetzner's
deterministic-name uniqueness to close the remaining provider race. A resource
created after a verified project snapshot is never silently swept into that
deletion; the final reinspection reports it as remaining instead. These
limitations are explicit consequences of an agentless, no-central-state
design.

`destroy.force = true` is narrow recovery for a machine whose remote lock
authority is unavailable. Core still requires destructive confirmation and
ownership-scoped provider discovery. Force never bypasses a lock known to be
held by another operation.
