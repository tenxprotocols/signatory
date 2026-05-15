# Tenx Signatory Fork

Private Tenx Protocols fork of [`ecadlabs/signatory`](https://github.com/ecadlabs/signatory). The fork tracks upstream and adds a small set of patches.

## Repo layout

Two long-lived branches:

| Branch | Role |
|---|---|
| `main` | Pure mirror of `ecadlabs/signatory:main`. Fast-forward only. Never modified directly. |
| `tenx-patches` *(default)* | `main` + Tenx CI overlay + Tenx code patches. Each patch is one commit. Force-pushed after upstream syncs. |

List every patch we carry:

```bash
git log --oneline main..tenx-patches
```

Today there are two:

- `ci(tenx): …` — workflow + runbook + deletion of upstream-specific workflows.
- `feat(rpc): …` — TCP reconnect for stale enclave sockets.

## Tags

| Tag form | Source | How it gets built |
|---|---|---|
| `vX.Y.Z` | Upstream tag, unchanged | Manual `workflow_dispatch` with `source_repo=ecadlabs/signatory` |
| `vX.Y.Z-tenx.N` | Upstream `vX.Y.Z` + our patches | Tag a short-lived `release/vX.Y.Z-tenx.N` branch and push |

`-tenx.N` is a SemVer-valid pre-release suffix.

## Build pipeline

`.github/workflows/tenx-release.yml` triggers on:

- **Tag push** matching `v*` — picks up `vX.Y.Z-tenx.N` tags.
- **Manual `workflow_dispatch`** with `ref:` and optional `source_repo:` — used to republish a vanilla upstream tag without first pushing it to our fork.

Images publish to:

- `ghcr.io/tenxprotocols/signatory:<tag>` (always).
- `<TENX_GAR_LOCATION>/<TENX_GAR_PROJECT>/<TENX_GAR_REPOSITORY>/signatory:<tag>` (when the GAR vars are set).

## Republishing an upstream tag (vanilla)

Use `workflow_dispatch` with `source_repo`. The upstream tag stays on upstream — we do not push it to our fork.

```bash
gh workflow run "Tenx Build & Release" \
  -R tenxprotocols/signatory \
  --ref tenx-patches \
  -f ref=v1.4.0 \
  -f source_repo=ecadlabs/signatory
```

Or in the UI: Actions → Tenx Build & Release → Run workflow → Use workflow from `tenx-patches` → `ref: v1.4.0` → `source_repo: ecadlabs/signatory`.

`source_repo` makes `actions/checkout` clone from upstream directly. Leave it empty when building a ref already on origin (any `vX.Y.Z-tenx.N` tag, any branch).

## Cutting a Tenx release

```bash
# 1. Fetch upstream tags if you don't already have them
git fetch upstream --tags

# 2. Start from the upstream tag we want as base
git checkout v1.4.0
git checkout -b release/v1.4.0-tenx.1

# 3. Replay every Tenx patch on top of the upstream tag
git cherry-pick main..tenx-patches

# 4. Tag and push -- CI sees the tag and publishes
git tag v1.4.0-tenx.1
git push origin v1.4.0-tenx.1
```

Bump `.N` for subsequent patched releases against the same upstream version (`v1.4.0-tenx.2`, …). When upstream cuts `v1.4.1`, reset to `v1.4.1-tenx.1`.

The `release/v1.4.0-tenx.1` branch is ephemeral; delete it after the tag is pushed.

## Syncing upstream

```bash
git fetch upstream

# 1. Fast-forward main to match upstream
git checkout main
git merge --ff-only upstream/main
git push origin main

# 2. Rebase tenx-patches; resolve conflicts where upstream touches files we patched
git checkout tenx-patches
git rebase main
git push --force-with-lease origin tenx-patches
```

If a patch becomes redundant (upstream accepts our PR, for example), drop the commit during the rebase. The fork shrinks.

## Adding a new patch

```bash
git checkout tenx-patches
# Develop, test, commit. One logical patch per commit.
git push origin tenx-patches
```

Consider upstreaming first. A patch that lands upstream is one less rebase conflict per upstream sync, and one less thing for us to maintain.

## What we don't carry from upstream

The CI overlay deletes two upstream workflow files because they cannot work on our fork:

- **`build.yaml`** is hardcoded to push to `ghcr.io/ecadlabs/signatory` and to log into Docker Hub. Without those credentials it fails on every push to our fork.
- **`check-octez-version.yml`** opens GitHub issues when new Tezos Octez versions drop. We don't run the integration suite that consumes those versions, so it would be noise on our fork.

`codeql-analysis.yml` is kept — it uses the default `GITHUB_TOKEN` and works on any repo.

The deletion is part of the CI overlay commit, so it re-applies cleanly when you rebase `tenx-patches` onto a refreshed `main`.

## One-time CI setup

**Repo variables** (Settings → Secrets and variables → Actions → Variables):

| Name | Example | Required? |
|---|---|---|
| `DOCKER_RELEASE_USER` | GHCR push username (PAT owner or bot account) | required |
| `TENX_GAR_LOCATION` | `us-east4-docker.pkg.dev` | optional |
| `TENX_GAR_PROJECT` | `tenx-blockchains` | optional (gates GAR push) |
| `TENX_GAR_REPOSITORY` | `signatory` | optional |

**Repo secrets** (same screen, Secrets tab):

| Name | Purpose |
|---|---|
| `DOCKER_RELEASE_TOKEN` | GHCR push token (PAT with `write:packages`) paired with `DOCKER_RELEASE_USER` |
| `TENX_GAR_WIF_PROVIDER` | Workload Identity Federation provider, e.g. `projects/<NUMBER>/locations/global/workloadIdentityPools/github-tenxprotocols-signatory/providers/github` |
| `TENX_GAR_SERVICE_ACCOUNT` | Service-account email with `roles/artifactregistry.createOnPushWriter` on the GAR repo |

If `TENX_GAR_PROJECT` is unset, GAR steps are skipped and CI publishes to GHCR only.
