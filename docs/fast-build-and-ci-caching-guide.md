# Lightrail Fast Build and CI/CD Caching Guide

This document details optimization strategies, caching configurations, static binary generation, and release workflows for Lightrail.

---

## 1. Fast Build Strategies

Compilation speed is critical for fast developer feedback and CI turnarounds. Lightrail provides multiple build modes in `Cargo.toml` and `Makefile`.

### Local Build Shortcuts

| Goal | Command | Description |
| --- | --- | --- |
| **Instant Check** | `cargo check --workspace` | Type-checks the entire workspace in <1 second without binary linking. |
| **Fast Release** | `make build-fast` | Uses `[profile.release-fast]` (`opt-level=2`, `codegen-units=16`, `lto=false`). ~3x faster compilation than full release. |
| **Full Release** | `make release` | Full optimization with thin LTO and `opt-level=3`. |
| **Static Release** | `make static` | Generates fully static binaries using `RUSTFLAGS="-C target-feature=+crt-static"`. |
| **Verbose Build** | `make release V=1` | Passes `-v` to `cargo build` for detailed compiler output. |

### Cargo Profile Tuning (`Cargo.toml`)

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 16

[profile.release-fast]
inherits = "release"
opt-level = 2
lto = false
codegen-units = 16
```

### Compiler Caching (`sccache`)

For faster local and CI recompilations across branches, enable `sccache`:

```console
cargo install sccache
export RUSTC_WRAPPER=sccache
make build
```

---

## 2. CI/CD Caching Setup

Lightrail uses GitHub Actions (`.github/workflows/ci.yml` and `.github/workflows/release.yml`) with automated caching.

### Cargo Dependency & Target Caching

We utilize `Swatinem/rust-cache@v2` with workspace-scoped cache keys:

```yaml
- name: Setup Cargo Cache
  uses: Swatinem/rust-cache@v2
  with:
    prefix-key: "v1-rust-ci"
    workspaces: ". -> target"
```

### Benefits:
- **Registry index & crate downloads** are persisted across workflow runs.
- **Compiled dependency artifacts** (`target/release/deps`) are reused, reducing CI build times from ~5 minutes to ~30 seconds on warm runs.

---

## 3. Static Binary Compilation

Lightrail supports static linking to produce standalone binaries without dynamic Glibc runtime dependencies.

### Building Static Binaries Locally

```console
make static
```

Or using explicit target flags:

```console
cargo build --release --target x86_64-unknown-linux-musl
```

All 6 output binaries in `target/release/` (or `target/x86_64-unknown-linux-musl/release/`) will be fully statically linked.

---

## 4. One-Line Installer & Release Cycle

### One-Line Bash Installer

Users can install or update Lightrail with a single terminal command:

```console
curl -fsSL https://raw.githubusercontent.com/gelleson/lightrail/main/install.sh | sh
```

Options via environment variables:
- `PREFIX=/usr/local`: Custom install target path.
- `VERSION=v0.1.0`: Pin to a specific version.
- `REPO=gelleson/lightrail`: Custom repository source.

### Release Cycle Workflow

1. **Gate Verification**:
   Ensure `make check` passes cleanly locally and on `main`.

2. **Tagging a Release**:
   ```console
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. **Automated Release Packaging**:
   Pushing a `v*` tag triggers `.github/workflows/release.yml`, which:
   - Builds matrix targets:
     - `x86_64-unknown-linux-musl` (Static Linux x86_64)
     - `aarch64-unknown-linux-musl` (Static Linux ARM64)
     - `x86_64-apple-darwin` (macOS Intel)
     - `aarch64-apple-darwin` (macOS Apple Silicon)
   - Bundles all 6 executables (`lightrail`, `lightrail-plugin-compose`, `lightrail-plugin-fly`, `lightrail-plugin-hetzner`, `lightrail-plugin-kubernetes`, `lightrail-plugin-ssh`).
   - Generates `.tar.gz` release archives and `.sha256` checksums.
   - Publishes a new GitHub Release automatically.
