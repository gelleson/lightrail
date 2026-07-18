# Single-app example

This project builds one tiny HTTP service locally and lets Lightrail deploy
the current Git branch to a remote target. The `hello` app receives a URL in
this form:

```text
https://<branch>.hello.preview.single-example.<8-hex-ip>.sslip.io
```

Copy this directory into its own Git repository; Lightrail always uses the
worktree and branch containing the current directory and does not need a
GitHub remote.

```console
cp -R examples/single-app ~/lightrail-single-example
cd ~/lightrail-single-example
git init
git switch -c feature-demo
git add .
git commit -m "Start single-app example"
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
IPv4 followed by `/32`. The image and committed configuration contain no
credentials. Lightrail builds from this checkout and transfers the result
directly to the configured host.

To remove the current branch environment:

```console
lightrail down --yes
```

For a provider-free syntax check, run:

```console
docker compose config --quiet
```
