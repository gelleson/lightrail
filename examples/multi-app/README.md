# Multi-app example

This project builds two independent HTTP services from one Git worktree.
Lightrail routes each selected app through its own branch-first hostname:

```text
https://<branch>.frontend.preview.multi-example.<8-hex-ip>.nip.io
https://<branch>.api.preview.multi-example.<8-hex-ip>.nip.io
```

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

Choose a target template, copy it to `lightrail.init.toml`, and replace its
`REPLACE` values:

```console
# Existing generic SSH host:
cp lightrail.init.ssh.example.toml lightrail.init.toml

# Or a dedicated Hetzner machine:
cp lightrail.init.hetzner.example.toml lightrail.init.toml
lightrail secret set hetzner-token

$EDITOR lightrail.init.toml
lightrail init --from lightrail.init.toml
rm lightrail.init.toml
git add lightrail.toml lightrail.lock .gitignore
git commit -m "Configure Lightrail"
lightrail up
lightrail urls
```

The Hetzner template expects an account SSH key whose matching private key is
available locally, plus a narrow operator CIDR such as your current public
IPv4 followed by `/32`. No provider credential belongs in either template.

`lightrail urls` prints both apps. Switching the worktree to another branch
and running `up` creates a separate pair of branch URLs. Destroy the current
branch environment with:

```console
lightrail down --yes
```

For a provider-free syntax check, run:

```console
docker compose config --quiet
```
