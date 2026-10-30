# Gateway API

tunnelgate can publish `HTTPRoute`s through a Tunnel. It is optional: the adapter starts once the
Gateway API CRDs (`gateway.networking.k8s.io/v1` GatewayClass, Gateway and HTTPRoute) are served,
checking at startup and then every 30 seconds, so installing Gateway API later needs no restart.
It supports **Gateway API v1.2 and later** (standard channel; tested against v1.2.0) and
coexists with other implementations such as Traefik: it only touches Gateways of its own class.

Each attached HTTPRoute becomes one `TunnelRoute` per hostname × path match, in the HTTPRoute's
namespace and owned by it. Everything else (tunnel configuration, DNS, conflicts, `Ready`) is
the TunnelRoute machinery, so `kubectl get tunnelroutes` shows what was published.

## Setup

The Helm chart creates the GatewayClass `tunnelgate` when the Gateway API CRDs are installed at
install or upgrade time (values `gatewayClass.create`, `gatewayClass.name`). Installed Gateway API
later? Run `helm upgrade`, or create it yourself:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: tunnelgate }
spec:
  controllerName: tunnelgate.geeko.me/tunnel
```

Then one Gateway per Tunnel, and HTTPRoutes from any namespace its listeners admit:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: tunnelgate
spec:
  gatewayClassName: tunnelgate
  infrastructure:
    parametersRef: { group: tunnelgate.geeko.me, kind: Tunnel, name: main }   # in this namespace
  listeners:
    - name: apps
      port: 80                                  # informational: Cloudflare terminates TLS
      protocol: HTTP
      hostname: "*.apps.example.com"        # optional; restricts the routes' hostnames
      allowedRoutes:
        namespaces: { from: All }               # Same (default), All or Selector
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: demo
  namespace: demo
  annotations:
    tunnelgate.geeko.me/origin-protocol: http   # optional, see below
spec:
  parentRefs: [{ name: public, namespace: tunnelgate, sectionName: apps }]
  hostnames: [demo.apps.example.com]
  rules:
    - matches: [{ path: { type: PathPrefix, value: /api } }]
      backendRefs: [{ name: demo-api, port: 8080 }]
    - backendRefs: [{ name: demo, port: 80 }]
```

```sh
kubectl wait --for=condition=Programmed gateway/public -n tunnelgate --timeout=5m
kubectl get httproute demo -n demo -o jsonpath='{.status.parents}'
```

### Naming the Tunnel

- **`spec.infrastructure.parametersRef`** (recommended): a Tunnel in the Gateway's own namespace.
  Gateway API defines this reference as local, so it can't point into another namespace.
- **Annotation `tunnelgate.geeko.me/tunnel: <name>` or `<namespace>/<name>`**: the fallback, and
  the only way to use a Tunnel in another namespace (which then needs a grant, see below). It
  also keeps Gateways working on older Gateway API bundles, where the API server drops the
  `infrastructure` field.

If both are set they must name the same Tunnel; otherwise the Gateway is not accepted.

## What is supported

| HTTPRoute feature | Support |
|---|---|
| `hostnames` (exact and `*.` wildcards) | ✅ intersected with the listener's hostname; a route needs a hostname from one of the two |
| `matches[].path` `PathPrefix` | ✅ element-wise: `/api` matches `/api` and `/api/x`, not `/apix` |
| `matches[].path` `Exact` | ✅ |
| `matches[].path` `RegularExpression` | ❌ `UnsupportedValue` |
| header, query parameter and method matches | ❌ `UnsupportedValue` |
| `filters` (route and backend) | ❌ `UnsupportedValue` |
| exactly one `backendRef` to a Service, with `port` | ✅ (`weight` is ignored unless 0) |
| several backendRefs, other backend kinds | ❌ `UnsupportedValue` |
| rule fields of later releases (`timeouts`, …) | ❌ `UnsupportedValue` (rule `name` is fine) |

Unsupported features reject the whole HTTPRoute on that parent (`Accepted=False`) instead of
publishing a route that behaves differently from what it says. For two rules with the same
hostname and path, the first wins.

Origin settings and Access come from **HTTPRoute annotations** and apply to every TunnelRoute it
generates:

| Annotation | Value | TunnelRoute field |
|---|---|---|
| `tunnelgate.geeko.me/origin-protocol` | `http` / `https` | `origin.protocol` |
| `tunnelgate.geeko.me/origin-server-name` | SNI / certificate name | `origin.serverName` |
| `tunnelgate.geeko.me/origin-no-tls-verify` | `true` / `false` | `origin.noTLSVerify` |
| `tunnelgate.geeko.me/access-applications` | comma-separated `[<namespace>/]<name>` | `access.applicationRefs` |

The Tunnel's `originDefaults` (CA pool, timeouts) apply as for any TunnelRoute.

## Who may use what

Gateway API rules, plus grants where Gateway API has no rule:

- **HTTPRoute → Gateway**: the listener's `allowedRoutes` (namespaces and kinds) and `hostname`.
  No grant: the Gateway owner decides who may attach.
- **Gateway → Tunnel** in another namespace: a `ReferenceGrant` or `RouteGrant` in the Tunnel's
  namespace from `group: gateway.networking.k8s.io, kind: Gateway`.
- **HTTPRoute → Service** in another namespace: a `ReferenceGrant` or `RouteGrant` in the
  Service's namespace from `group: gateway.networking.k8s.io, kind: HTTPRoute`, as in Gateway API.

Generated TunnelRoutes carry the Gateway they come from (annotation `tunnelgate.geeko.me/gateway`),
and their tunnel reference is accepted when that Gateway admits the route's namespace and
hostname. A hand-written TunnelRoute with the same annotation gets exactly what an HTTPRoute in
its namespace could get, nothing more.

## Status

- **GatewayClass**: `Accepted=True` for `controllerName: tunnelgate.geeko.me/tunnel`.
- **Gateway**: `Accepted` (the Tunnel reference resolves and is permitted; reasons
  `InvalidParameters` for a missing, malformed, contradictory or not-found Tunnel reference, and
  `RefNotPermitted`), `Programmed` (the Tunnel is `Ready`), `addresses` = the
  tunnel's `<id>.cfargotunnel.com`, and per listener `supportedKinds`, `attachedRoutes` and
  conditions (non-HTTP/HTTPS listeners: `Accepted=False, reason=UnsupportedProtocol`).
- **HTTPRoute** (`status.parents`, our entries only):
  - `Accepted`: `NotAllowedByListeners`, `NoMatchingListenerHostname`, `NoMatchingParent`,
    `UnsupportedValue`, or a TunnelRoute rejection carried over (`Conflict`, `ZoneNotFound`, …).
    The message lists the generated TunnelRoutes.
  - `ResolvedRefs`: `RefNotPermitted` or `BackendNotFound` from the generated TunnelRoutes.

## Limitations

- Cloudflare matches ingress rules in order, and tunnelgate orders paths longest first. A
  `PathPrefix` and an `Exact` match on the same path with different backends don't follow Gateway
  API's "Exact wins" precedence: avoid that combination.
- Listener `port`, `protocol: HTTPS` and `tls` are not used: Cloudflare's edge terminates TLS with
  the zone's certificate. `HTTPS` listeners are accepted so existing Gateways can be reused.
- Changes to a Gateway's listeners re-evaluate generated routes right away; hand-written
  TunnelRoutes that name a Gateway are re-checked at the next resync (10 minutes by default).
