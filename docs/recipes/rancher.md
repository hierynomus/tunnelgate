# Recipe: Rancher behind the tunnel

> **Status:** the resources below work with the fake API in the controller tests, not yet run
> against a real Rancher. The agent path list is a candidate list; please report paths that turn
> out to be missing.

Rancher's UI sits behind a Cloudflare Access login; Rancher's agents (non-browser clients) reach
the API paths they need through a Bypass on the same hostname. This version uses a `TunnelRoute`
to Rancher's existing ingress; with the Gateway API, see
[rancher-gateway-api.md](rancher-gateway-api.md) (no ingress or in-cluster certificates needed).

## Prerequisites

- Rancher serves a **publicly trusted certificate** (production Let's Encrypt).
- Rancher setting **`agent-tls-mode: system-store`**. With a private/staging CA and `strict`,
  agents compare Rancher's CA checksum and reject Cloudflare's edge certificate.

## Resources

```yaml
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: CloudflareAccount                # cluster-scoped
metadata: { name: main }
spec:
  accountId: <account id>
  credentialsSecretRef: { name: cloudflare-api, namespace: tunnelgate }
  allowedNamespaces: [tunnelgate, cattle-system]
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: TunnelRoute
metadata: { name: rancher, namespace: kube-system }
spec:
  tunnelRef: { name: main, namespace: tunnelgate }   # needs a RouteGrant in tunnelgate
  hostname: rancher.example.com
  service: { backendRef: { name: rke2-traefik, port: 443 } }
  origin:
    protocol: https
    serverName: rancher.example.com
    httpHostHeader: rancher.example.com
  access:
    applicationRefs:
      - { name: rancher-ui, namespace: cattle-system }
      - { name: rancher-agents, namespace: cattle-system }
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: RouteGrant
metadata: { name: routes-from-kube-system, namespace: tunnelgate }
spec:
  from: [{ group: tunnelgate.geeko.me, kind: TunnelRoute, namespace: kube-system }]
  to: [{ group: tunnelgate.geeko.me, kind: Tunnel, name: main }]
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: AccessPolicy
metadata: { name: admins, namespace: tunnelgate }
spec:
  cloudflare: { accountRef: main }
  decision: allow
  include:
    - emails: [admin@example.com]
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: AccessPolicy
metadata: { name: bypass-everyone, namespace: tunnelgate }
spec:
  cloudflare: { accountRef: main }
  decision: bypass
  include:
    - everyone: true
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: AccessApplication
metadata: { name: rancher-ui, namespace: cattle-system }
spec:
  cloudflare: { accountRef: main }
  name: Rancher
  destinations: [rancher.example.com]
  policies: [{ name: admins, namespace: tunnelgate }]
  sessionDuration: 24h
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: AccessApplication
metadata: { name: rancher-agents, namespace: cattle-system }
spec:
  cloudflare: { accountRef: main }
  name: Rancher agents
  destinations:                       # candidate list
    - rancher.example.com/v3/connect
    - rancher.example.com/v3/import
    - rancher.example.com/cacerts
    - rancher.example.com/ping
    - rancher.example.com/healthz
    - rancher.example.com/assets
    - rancher.example.com/system-agent-install.sh
    - rancher.example.com/v1-rke2-release
    - rancher.example.com/v1-k3s-release
  policies: [{ name: bypass-everyone, namespace: tunnelgate }]
```

Open points: whether Fleet agents need `/k8s/clusters/`, idle timeouts on the
`/v3/connect` websocket, and whether cloudflared needs `keepAliveTimeout`/`noHappyEyeballs`
tuning (`origin.keepAliveTimeout`, `origin.noHappyEyeballs` on the route).
