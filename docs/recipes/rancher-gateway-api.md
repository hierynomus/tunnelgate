# Recipe: Rancher through the Gateway API

> **Status:** built from features covered by the controller tests, not yet run against a real
> Rancher. The agent path list is a candidate list; please report paths that turn out to be
> missing.

Rancher is published with a standard `HTTPRoute`; no Ingress, no ingress controller and no
certificate management in the cluster. Cloudflare's edge serves the public certificate, the
tunnel carries the traffic to the Rancher Service, and Cloudflare Access protects the UI while
Rancher's agents (non-browser clients) reach the paths they need through a Bypass on the same
hostname.

Roles are split the Gateway API way:

- the **platform team** owns the Tunnel, the Gateway and its listener for `rancher.example.com`,
  and the Access policies;
- the **Rancher installation** (namespace `cattle-system`) owns its HTTPRoute and Access
  applications.

For the same setup without the Gateway API, see [rancher.md](rancher.md).

## Prerequisites

- tunnelgate installed with the Gateway API CRDs (v1.2+) present, so the chart created the
  `tunnelgate` GatewayClass ([gateway-api.md](../gateway-api.md)).
- A `Tunnel` named `main` in namespace `tunnelgate`, as in the README quick start.
- Rancher installed with TLS terminated outside it and without its Ingress, and agents trusting
  the system certificate store (Cloudflare's edge certificate is publicly trusted, so the default
  `strict` mode, which pins Rancher's own CA, would reject it):

  ```sh
  helm upgrade --install rancher rancher-stable/rancher -n cattle-system --create-namespace \
    --set hostname=rancher.example.com \
    --set tls=external \
    --set ingress.enabled=false \
    --set agentTLSMode=system-store
  ```

## Platform: Gateway, account and policies

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: public, namespace: tunnelgate }
spec:
  gatewayClassName: tunnelgate
  infrastructure:
    parametersRef: { group: tunnelgate.geeko.me, kind: Tunnel, name: main }
  listeners:
    - name: rancher
      port: 80                          # informational: Cloudflare terminates TLS
      protocol: HTTP
      hostname: rancher.example.com     # only this hostname, and only from cattle-system
      allowedRoutes:
        namespaces:
          from: Selector
          selector: { matchLabels: { kubernetes.io/metadata.name: cattle-system } }
---
apiVersion: tunnelgate.geeko.me/v1alpha1
kind: CloudflareAccount                 # cluster-scoped
metadata: { name: main }
spec:
  accountId: <account id>
  credentialsSecretRef: { name: cloudflare-api, namespace: tunnelgate }
  allowedNamespaces: [tunnelgate, cattle-system]
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
```

## Rancher: route and Access applications

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: rancher
  namespace: cattle-system
  annotations:
    tunnelgate.geeko.me/origin-protocol: http                       # Rancher with tls=external
    tunnelgate.geeko.me/access-applications: rancher-ui,rancher-agents
spec:
  parentRefs: [{ name: public, namespace: tunnelgate, sectionName: rancher }]
  hostnames: [rancher.example.com]
  rules:
    - backendRefs: [{ name: rancher, port: 80 }]
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
  destinations:                         # candidate list
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

Cloudflare Access matches the most specific destination, so the agent paths get the Bypass and
everything else on the hostname requires the `admins` login.

## Check

```sh
kubectl -n tunnelgate wait --for=condition=Programmed gateway/public --timeout=5m
kubectl -n cattle-system get httproute rancher -o jsonpath='{.status.parents}'
kubectl -n cattle-system wait --for=condition=Ready accessapplication/rancher-ui \
  accessapplication/rancher-agents --timeout=5m
kubectl -n cattle-system get tunnelroutes          # the route generated from the HTTPRoute
```

Then open `https://rancher.example.com`: you get the Access login first, then Rancher.

## Split-horizon DNS

With split horizon, clients on the LAN resolve `rancher.example.com` to an internal address and
reach the cluster directly, without Cloudflare. That path needs its own TLS, with a **publicly
trusted** certificate for the same hostname: agents use the system trust store
(`agentTLSMode=system-store`) and must accept both Cloudflare's edge certificate and the internal
one. A private CA would need `strict` mode, which rejects Cloudflare's certificate.

The Gateway API way: the same HTTPRoute attaches to two Gateways. tunnelgate's Gateway publishes
it through the tunnel; a Gateway of another implementation already in the cluster (Traefik, Envoy
Gateway, Cilium, …) serves it on the LAN and terminates TLS there. Rancher stays on
`tls=external` behind both: TLS ends at Cloudflare on one path and at the internal Gateway on the
other, and both set `X-Forwarded-Proto`.

The certificate comes from cert-manager with a DNS-01 challenge through the Cloudflare API. That
works for a hostname that's behind Access or only resolvable internally; HTTP-01 would need the
challenge path to reach the cluster through the tunnel and bypass Access. Give cert-manager its
own token (Zone: DNS: Edit on this zone only) rather than tunnelgate's.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: letsencrypt-dns }
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef: { name: letsencrypt-dns }
    solvers:
      - dns01:
          cloudflare:
            apiTokenSecretRef: { name: cloudflare-dns, key: api-token }   # in cert-manager's namespace
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: rancher-tls, namespace: gateways }   # the internal Gateway's namespace
spec:
  secretName: rancher-tls
  dnsNames: [rancher.example.com]
  issuerRef: { kind: ClusterIssuer, name: letsencrypt-dns }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: internal, namespace: gateways }
spec:
  gatewayClassName: traefik             # your LAN-facing implementation
  listeners:
    - name: rancher
      port: 443                         # the port your implementation expects for HTTPS
      protocol: HTTPS
      hostname: rancher.example.com
      tls:
        mode: Terminate
        certificateRefs: [{ name: rancher-tls }]
      allowedRoutes:
        namespaces:
          from: Selector
          selector: { matchLabels: { kubernetes.io/metadata.name: cattle-system } }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute                         # replaces the HTTPRoute above
metadata:
  name: rancher
  namespace: cattle-system
  annotations:                          # read by tunnelgate only
    tunnelgate.geeko.me/origin-protocol: http
    tunnelgate.geeko.me/access-applications: rancher-ui,rancher-agents
spec:
  parentRefs:
    - { name: public, namespace: tunnelgate, sectionName: rancher }   # internet: Cloudflare, tunnel
    - { name: internal, namespace: gateways, sectionName: rancher }   # LAN
  hostnames: [rancher.example.com]
  rules:
    - backendRefs: [{ name: rancher, port: 80 }]
```

Finally, point `rancher.example.com` at the internal Gateway's address in your internal DNS.
Public DNS keeps the proxied record tunnelgate manages.

- Each implementation reports only its own entry in the HTTPRoute's `status.parents`, so both
  show up side by side; tunnelgate ignores parents of other classes.
- **Access doesn't apply on the LAN**: Cloudflare isn't in the path there, so Rancher's own login
  is the only protection for the UI. If LAN users must go through Access too, don't use split
  horizon.
- The internal Gateway must pass websockets through (most do), for the agents' `/v3/connect`.

## Notes

- **Traffic inside the cluster is plain HTTP** from the cloudflared pods to the Rancher Service.
  To keep it encrypted, leave Rancher on its default `tls=ingress` and point the route at the
  Service's `https-internal` port (`port: 443`) with annotations `origin-protocol: https` and
  `origin-no-tls-verify: "true"`, or `origin-server-name` plus a CA pool on the Tunnel
  (`originDefaults`) to verify Rancher's self-signed certificate.
- **The listener restricts the route**: an HTTPRoute in any other namespace, or for another
  hostname, isn't accepted on this listener (`NotAllowedByListeners`,
  `NoMatchingListenerHostname`).
- Long-lived agent websockets (`/v3/connect`): if they drop at idle, tune
  `originDefaults.keepAliveTimeout` on the Tunnel.
