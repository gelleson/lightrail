# Multi-app example

This project builds two independent HTTP services from one Git worktree. On
SSH, Hetzner, and Kubernetes, Lightrail routes each selected app through its
own branch-first hostname:

```text
https://<branch>.frontend.preview.multi-example.<8-hex-ip>.nip.io
https://<branch>.api.preview.multi-example.<8-hex-ip>.nip.io
```

Fly uses deterministic provider-native `.fly.dev` URLs reported by
`lightrail urls`.

Copy this directory into its own Git repository. No GitHub or other Git host
is required.

```console
cp -R examples/multi-app ~/lightrail-multi-example
cd ~/lightrail-multi-example
git init
git switch -c feature-two-apps
git add .
git commit -m "Start multi-app example"
```

Choose one target template and replace its `REPLACE` values.

For an existing generic SSH host:

```console
cp lightrail.init.ssh.example.toml lightrail.init.toml
$EDITOR lightrail.init.toml
lightrail init --from lightrail.init.toml
```

For a dedicated Hetzner machine:

```console
cp lightrail.init.hetzner.example.toml lightrail.init.toml
$EDITOR lightrail.init.toml
lightrail init --from lightrail.init.toml
# Optional: store the token once instead of entering it during each command.
lightrail secret set hetzner-token
```

For an existing Kubernetes cluster:

```console
cp lightrail.init.kubernetes.example.toml lightrail.init.toml
$EDITOR lightrail.init.toml
lightrail init --from lightrail.init.toml
```

For Fly.io:

```console
cp lightrail.init.fly.example.toml lightrail.init.toml
$EDITOR lightrail.init.toml
lightrail init --from lightrail.init.toml
lightrail secret set fly-token
```

Then review and deploy:

```console
rm lightrail.init.toml
git add lightrail.toml lightrail.lock .gitignore
git commit -m "Configure Lightrail"
lightrail doctor --target
lightrail up --dry-run
lightrail up
```

The Hetzner template expects an account SSH key whose matching private key is
available locally, plus a narrow operator CIDR such as your current public
IPv4 followed by `/32`. Kubernetes expects the named context, control
namespace, IngressClass, exact LoadBalancer Service backing that class,
ClusterIssuer, and registry access to exist. Replace the example Service
namespace/name with the cluster's actual values. No provider credential
belongs in any template.

`up` prints both app URLs; `lightrail -o plain urls` prints only their raw
values. Switching the worktree to another branch and running `up` creates a
separate pair of branch URLs. Destroy the current branch environment with:

```console
lightrail down --yes
```

For a provider-free syntax check, run:

```console
docker compose config --quiet
```
