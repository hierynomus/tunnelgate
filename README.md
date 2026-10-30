# tunnelgate

Publish services from any Kubernetes cluster to the internet **without exposing the cluster**:
no public IP, no load balancer, no open inbound ports, no VPN. tunnelgate runs a
**Cloudflare Tunnel** connector in the cluster (outbound connections only) and manages the
tunnel, its routes, public DNS and **Cloudflare Access** (zero-trust login in front of your apps)
declaratively, from Kubernetes resources.

It fits private, on-prem, edge and NAT'ed clusters (k3s, RKE2, home labs, CI and demo
environments) that need public or Access-protected endpoints with minimal infrastructure, managed
the same way as everything else in the cluster (GitOps, Helm, `kubectl`).

- **Gateway API native.** Built on the Kubernetes Gateway API (v1.2+), the successor to Ingress:
  apps ship a standard `HTTPRoute`, the platform team owns the `Gateway` that binds it to a
  tunnel. Routes stay portable across implementations, roles are separated, and cross-namespace
  use needs an explicit grant, all without controller-specific annotations
  ([docs/gateway-api.md](docs/gateway-api.md)). There's no Ingress support, by design; clusters
  without the Gateway API use the `TunnelRoute` CRD instead.
- Remote-managed tunnels with an in-cluster connector using the **official** `cloudflared` image.
- Per-route origin settings: hostname (+ optional path) → Service or URL, HTTPS, SNI, Host
  header, CA pool, HTTP/2, timeouts.
- Proxied DNS records with ownership markers; never touches records it doesn't own (unless
  `adopt: true`).
- Access applications with **path-scoped destinations** and reusable policies, including Bypass;
  service tokens with credentials in a Secret (rotated when the Secret is lost).
- Every resource reports a `Ready` condition (plus detail conditions with specific reasons), so
  `kubectl wait --for=condition=Ready` tells you when everything is provisioned.
- Stays within Cloudflare's API rate limit (client-side budget per token, backoff on 429/5xx),
  and a restarted or upgraded operator takes over without rewriting anything in Cloudflare.
- `tunnelgate sweep` finds everything a cluster left behind in Cloudflare.

## Status

Early (`v1alpha1`). Tunnels, routes, DNS, Access, the Gateway API adapter, sweep, rate limits and
signed releases are implemented, tested against a fake Cloudflare API on k3d, and verified end to
end against a real Cloudflare account with a real cloudflared. No release has been tagged yet.

## Quick start

Install the operator and give it a Cloudflare API token, then create a Tunnel. The cluster then
has one tunnel with its own `cloudflared`, and everything you publish goes through it.

```sh
helm install tunnelgate oci://ghcr.io/hierynomus/charts/tunnelgate -n tunnelgate --create-namespace
kubectl -n tunnelgate create secret generic cloudflare-api --from-literal=CLOUDFLARE_API_TOKEN=…
```

```yaml
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: Tunnel
metadata: { name: main, namespace: tunnelgate }
spec:
  cloudflare:
    accountId: <account id>
    credentialsSecretRef: { name: cloudflare-api }
```

Then publish apps in one of two ways.

### With Gateway API: apps ship an `HTTPRoute`

If the Gateway API CRDs (v1.2+) are installed, the chart creates a `tunnelgate` GatewayClass.
Create one Gateway that points at the Tunnel and admits routes from the namespaces you want:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: tunnelgate
spec:
  gatewayClassName: tunnelgate
  infrastructure:
    parametersRef: { group: tunnelgate.geeko.me, kind: Tunnel, name: main }
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      hostname: "*.apps.example.com"   # optional: limits which hostnames routes may use
      allowedRoutes: { namespaces: { from: All } }
```

From then on an app needs nothing tunnelgate-specific: the `HTTPRoute` its Helm chart (or
manifest) already ships is published as soon as its `parentRefs` point at that Gateway. You don't
write TunnelRoutes; tunnelgate generates them (one per hostname and path, owned by the HTTPRoute,
deleted with it).

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: demo, namespace: demo }
spec:
  parentRefs: [{ name: public, namespace: tunnelgate }]
  hostnames: [demo.apps.example.com]
  rules:
    - backendRefs: [{ name: demo, port: 80 }]
```

```sh
kubectl -n demo get httproute demo -o jsonpath='{.status.parents}'   # Accepted / ResolvedRefs
```

Access applications and origin settings (HTTPS to the backend, SNI, …) are set with annotations on
the HTTPRoute. Filters, header/query matches and several backends per rule aren't supported and are
rejected rather than half-applied: [docs/gateway-api.md](docs/gateway-api.md).

### Without Gateway API: a `TunnelRoute`

A `TunnelRoute` maps a hostname (and optional path) to a Service or URL directly, with all origin
and Access settings as fields:

```yaml
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: TunnelRoute
metadata: { name: demo, namespace: tunnelgate }
spec:
  tunnelRef: { name: main }
  hostname: demo.apps.example.com
  service: { backendRef: { name: demo, port: 80 } }
```

```sh
kubectl -n tunnelgate wait --for=condition=Ready tunnel/main tunnelroute/demo --timeout=5m
```

A route in another namespace than its Tunnel needs a `RouteGrant` (or Gateway API
`ReferenceGrant`) in the Tunnel's namespace; see [docs/crds.md](docs/crds.md).

Field reference: [docs/crds.md](docs/crds.md). Token permissions:
[docs/permissions.md](docs/permissions.md). Conditions and reasons:
[docs/conditions.md](docs/conditions.md). Gateway API: [docs/gateway-api.md](docs/gateway-api.md).
Rancher behind Access: with the Gateway API
([docs/recipes/rancher-gateway-api.md](docs/recipes/rancher-gateway-api.md)) or a TunnelRoute
([docs/recipes/rancher.md](docs/recipes/rancher.md)).

## Leftovers

`tunnelgate sweep` needs only an API token and the cluster ID (the UID of the cluster's
`kube-system` namespace), so it works after the cluster is gone:

```sh
kubectl get namespace kube-system -o jsonpath='{.metadata.uid}'   # note it while the cluster exists
export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…
tunnelgate sweep --cluster-id <uid> --dry-run --fail-on-leftovers   # exit 3 when anything is left
tunnelgate sweep --cluster-id <uid>                                  # delete it
```

It deletes everything marked for that cluster, so don't run it without `--dry-run` while the
operator is still running there. Zones the token may not read DNS in are reported as skipped.

## Releases

Pushing a tag `vX.Y.Z` releases version X.Y.Z; the tag is the only place the version is set
(`Cargo.toml` and `Chart.yaml` hold a `0.0.0-dev` placeholder). A release publishes
`ghcr.io/hierynomus/tunnelgate` (amd64, arm64), the chart `oci://ghcr.io/hierynomus/charts/tunnelgate`
(pinned to the image digest), and a GitHub release with the `tunnelgate` CLI, `crds.yaml`, an SPDX
SBOM and checksums. Images, chart and checksums are
signed with cosign (keyless):

```sh
cosign verify ghcr.io/hierynomus/tunnelgate:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/hierynomus/tunnelgate/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Release notes are GitHub's generated notes, sectioned by PR label (`.github/release.yml`). PRs are
labelled from their changed paths and title; add `skip-changelog` to leave one out.

## Development

All tools are pinned in `mise.toml`:

```sh
mise install
mise run lint          # fmt check, clippy -D warnings, cargo deny
mise run test          # unit tests (render logic, client vs fake API, snapshots)
mise run test-cluster  # controllers in-process against k3d + the fake Cloudflare API
                       # (Docker, or rootless Podman: see below)
mise run test-live     # contract test against the live Cloudflare API   } need mise.local.toml
mise run test-e2e      # operator + real cloudflared in k3d, live API    } (see docs/permissions.md)
mise run crds          # regenerate charts/tunnelgate/crds and docs/crds.md from the Rust types
VERSION=0.1.0 mise run dist   # release assets in target/dist (CLI tarballs, crds.yaml, chart)
mise run image         # multi-arch image (Docker buildx)
```

The test cluster runs on Docker or **rootless Podman**. For Podman, enable the socket
(`systemctl --user enable --now podman.socket`) and delegate cgroup controllers to your user
session once, then log in again:

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nDelegate=cpu cpuset io memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf
sudo systemctl daemon-reload
```

`cluster-up` handles the rest; the workarounds it applies are explained in the task in `mise.toml`.

| Crate | |
|---|---|
| `tunnelgate-api` | CRD types (`v1alpha1`), condition types/reasons |
| `tunnelgate-cf` | Cloudflare client: `CloudflareApi` trait + reqwest/rustls implementation with retries and a rate budget |
| `tunnelgate-cf-fake` | in-process fake Cloudflare API with request log and fault injection |
| `tunnelgate-render` | pure logic: ingress ordering/conflicts/hash, DNS planning, Access rendering, markers, sweep |
| `tunnelgate-operator` | controllers and the `tunnelgate-operator` binary |
| `tunnelgate-cli` | the `tunnelgate` binary: `crdgen` (YAML or `--markdown`), `sweep`; its library is shared with the e2e test |
