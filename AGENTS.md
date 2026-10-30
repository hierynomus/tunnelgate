# AGENTS.md

Guidance for coding agents (and humans) contributing to **tunnelgate**.

## What tunnelgate is for

tunnelgate makes services in a Kubernetes cluster reachable from the internet **without exposing
the cluster**: no public IP, no load balancer, no inbound firewall ports, no VPN. It runs a
Cloudflare Tunnel connector inside the cluster (outbound connections only) and manages everything
around it declaratively: the tunnel, its routes, public DNS records and Cloudflare Access
(zero-trust login in front of an app).

- **Built on the Kubernetes Gateway API**, the successor to Ingress. Applications ship a standard
  `HTTPRoute`; the platform team owns the `Gateway` that binds it to a tunnel. Apps stay portable
  (the same route works with any Gateway API implementation), roles are separated, and the richer
  routing model (path matches, cross-namespace references with explicit grants) needs no
  controller-specific annotations. There is no Ingress support, by design. Clusters without the
  Gateway API use tunnelgate's own `TunnelRoute` CRD, which has the same features.
- **Secure by default**: apps can be put behind Cloudflare Access per hostname or path; the
  operator only touches Cloudflare objects it owns and never overwrites existing DNS unless told
  to adopt it.
- **Automation-friendly**: every resource reports a `Ready` condition with specific reasons, so
  GitOps tools, pipelines and `kubectl wait` know when a service is actually reachable.
- **Operationally safe**: restarts and upgrades don't rewrite anything in Cloudflare, API rate
  limits are respected, and `tunnelgate sweep` finds anything a deleted cluster left behind.

Typical users: private, on-prem, edge and NAT'ed clusters (k3s, RKE2, home labs, CI and demo
environments) that need public or Access-protected endpoints with minimal infrastructure.

## Read first

| File | What's in it |
|---|---|
| `docs/gateway-api.md` | The Gateway API adapter (v1.2+; a Gateway names its Tunnel via `infrastructure.parametersRef`, or an annotation for cross-namespace). |
| `docs/conditions.md` | Status conditions and reasons per CRD. |
| `docs/crds.md` | Generated field reference (`mise run crds`); never edit by hand. |
| `docs/permissions.md` | Cloudflare API token permissions (account API token preferred). |
| `README.md` | User-facing overview, quick start, development, releases. |

## Layout

| Crate | Role |
|---|---|
| `tunnelgate-api` | CRD types (`tunnelgate.geeko.me/v1alpha1`), condition types/reasons, the `DOMAIN` constant. Schema snapshots in `src/snapshots`. |
| `tunnelgate-cf` | Cloudflare client: `CloudflareApi` trait, reqwest/rustls implementation, retries, token-bucket rate limit (`limit.rs`). |
| `tunnelgate-cf-fake` | In-process fake Cloudflare API with request log and fault injection, for unit and cluster tests. |
| `tunnelgate-render` | Pure logic, no I/O: ingress ordering/hash, DNS planning, Access rendering, ownership markers, sweep, Gateway API mapping. Put logic here when it can be tested without a cluster. |
| `tunnelgate-operator` | Controllers (`tunnel/`, `access/`, `route.rs`, `gateway.rs`, `account.rs`, `grants.rs`, `leader.rs`) and the `tunnelgate-operator` binary. |
| `tunnelgate-cli` | `tunnelgate` binary (`crdgen [--markdown]`, `sweep`) and a library (`find_leftovers`, `delete_leftover`) shared with the e2e test. |

Also: `charts/tunnelgate` (Helm chart; `crds/` is generated), `Dockerfile` (copies prebuilt static
musl binaries onto a digest-pinned SUSE BCI Minimal base), `.github/` (CI, release, labeler,
Dependabot).

## Tooling

Everything is pinned in `mise.toml` (`mise install`); don't install tools globally or use `curl | sh`.

```sh
mise run fmt           # cargo fmt
mise run lint          # fmt check, clippy -D warnings, cargo deny
mise run test          # unit tests: no cluster, no Cloudflare
mise run crds          # regenerate chart CRDs + docs/crds.md (CI fails if they differ)
mise run chart         # helm lint + package
mise run cluster-up    # throwaway k3d cluster, kubeconfig in target/k3d-kubeconfig
mise run test-cluster  # controllers in-process against k3d + the fake Cloudflare API
mise run test-live     # contract tests against the real Cloudflare API  (credentials needed)
mise run test-e2e      # operator + real cloudflared in k3d, real API      (credentials needed)
VERSION=x.y.z mise run dist  # release assets in target/dist
```

- Snapshot tests use `insta` (`cargo insta review`); `*.snap.new` is gitignored.
- Changed a CRD type? Run `mise run crds` and commit the regenerated files.
- Before calling work done: `mise run lint`, `mise run test`, and `mise run test-cluster` when
  controllers changed. Changes to the Cloudflare client, tunnel/DNS flow or Gateway adapter are
  worth a `test-e2e` run.
- Gated test suites only run when their task sets the env var: `TUNNELGATE_CLUSTER_TESTS`,
  `TUNNELGATE_LIVE_TESTS`, `TUNNELGATE_E2E_TESTS`.
- `cluster-up` works with Docker or rootless Podman (setup in the README; the k3d workarounds are
  explained in the task). It installs the Gateway API CRDs at `GATEWAY_API_VERSION`, the oldest
  supported release (v1.2.0).
- Code style: `rustfmt.toml` (max width 120), clippy clean with `-D warnings`. Comments explain
  *why*, sparingly; match the surrounding density.

## Tests against a real Cloudflare account

- Credentials come from environment variables `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and
  `CLOUDFLARE_TEST_ZONE`, typically loaded by a gitignored `mise.local.toml`
  (`[env] _.file = "<path to an env file outside the repo>"`). Use a dedicated test zone and a
  token with only the permissions in `docs/permissions.md`.
- **Never print the token.** Don't `cat` env files, run `env`/`printenv`, or use `set -x`. For an
  ad-hoc API call, pass the header via stdin and print only non-secret fields:
  `printf 'Authorization: Bearer %s\n' "$CLOUDFLARE_API_TOKEN" | curl -s -H @- https://api.cloudflare.com/client/v4/… | jq '.success'`
- Live and e2e tests only create and delete objects whose names start with **`tg-spike-`**; keep
  it that way, and never touch anything else in the account.
- Agents: these tests write to someone's real Cloudflare account. Ask before running them.
- Known e2e quirk: public resolvers can cache NXDOMAIN for a fresh hostname for up to 30 minutes;
  the e2e test falls back to the zone's already-resolved edge IPs (see `Edge` in `tests/e2e.rs`).
- Leftovers: `tunnelgate sweep --cluster-id <kube-system namespace UID> --dry-run`.

## Operator invariants (don't break these)

- Never log or put in errors/status: API tokens, tunnel connector tokens, service-token secrets,
  Access JWTs. Redact secrets in errors.
- Only modify Cloudflare objects tunnelgate owns (ownership markers and names derived from the
  cluster ID; see `crates/tunnelgate-render/src/marker.rs`). Existing DNS records are only taken
  over with an explicit `dns.adopt`.
- Least privilege for the API token and for the chart's RBAC.
- Reconciles are idempotent and restart-safe: a restart, or a restore without status, must cause
  **no Cloudflare writes** (the `takeover_writes_nothing` cluster test).
- All Cloudflare calls go through the client, which keeps the rate budget (default 3 req/s,
  burst 100) and backs off on 429/5xx.
- Every CRD reports a `Ready` condition with specific reasons (`docs/conditions.md`); Gateway API
  objects use the upstream conditions and reasons (e.g. `Accepted=False` / `InvalidParameters`).
- Gateway API first: new routing features land in the Gateway API adapter and `TunnelRoute`
  alike. No Ingress support.

## CI and releases

- `.github/workflows/ci.yml`: lint, test, CRD drift, chart, and the cluster tests. Caching via
  GitHub's `actions/cache` only.
- `.github/workflows/release.yml` on `v*.*.*` tags: the tag must match the crate version; no
  caches; multi-arch image with provenance, SBOM attestation and keyless cosign signatures; OCI
  chart pinned to the image digest; GitHub release with generated notes. Registry login only via
  `docker/login-action` (Helm and cosign reuse it).
- Release-note sections come from PR labels (`.github/release.yml`), set by
  `.github/workflows/labeler.yml`; `skip-changelog` leaves a PR out.
- Prefer GitHub's own actions (`actions/*`) and official vendor actions, pinned by commit SHA with
  a version comment. Pin images by digest: the base image, and the default cloudflared image
  (`crates/tunnelgate-operator/src/context.rs`, chart values, snapshot). Dependabot updates
  actions, the base image and crates; cloudflared is bumped by hand.

## Working agreements

- Don't commit, push, tag or open PRs unless asked.
- Keep docs in step with code in the same change: `docs/conditions.md`, `docs/gateway-api.md`,
  `docs/permissions.md`, `README.md`, and `docs/crds.md` (generated).
- Explain design decisions where they live: in module docs (`//!`) and comments at the code that
  implements them, and in the PR description.
