# CRD reference

Generated from the Rust types by `tunnelgate crdgen --markdown` (`mise run crds`); do not edit.
Conditions, reasons and their meaning are in [conditions.md](conditions.md).

- [CloudflareAccount](#cloudflareaccount)
- [Tunnel](#tunnel)
- [TunnelRoute](#tunnelroute)
- [AccessPolicy](#accesspolicy)
- [AccessApplication](#accessapplication)
- [AccessServiceToken](#accessservicetoken)
- [RouteGrant](#routegrant)

## CloudflareAccount

`tunnelgate.geeko.me/v1alpha1`, cluster, short names: `cfa`.

### spec

A Cloudflare account and its credentials, usable from other resources via
`cloudflare.accountRef`.

| Field | Type | Description |
|---|---|---|
| `accountId` | string |  |
| `accountName` | string |  |
| `allowedNamespaces` | []string | Namespaces whose resources may use this account; `*` allows all. Default: only the credentials Secret's namespace. |
| `credentialsSecretRef` | object, required |  |
| `credentialsSecretRef.key` | string | Defaults to `CLOUDFLARE_API_TOKEN`. |
| `credentialsSecretRef.name` | string, required |  |
| `credentialsSecretRef.namespace` | string, required |  |

### status

| Field | Type | Description |
|---|---|---|
| `accountId` | string |  |
| `conditions` | []object |  |
| `observedGeneration` | integer |  |

## Tunnel

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `tun`.

### spec

One Cloudflare Tunnel (remote-managed) and its in-cluster `cloudflared` connector.

| Field | Type | Description |
|---|---|---|
| `adopt` | boolean | Take over an existing Cloudflare tunnel with this name that isn't recorded as ours (tunnels with the default name, which includes the cluster ID, are always taken over). Default `false`. |
| `cloudflare` | object, required | Which Cloudflare account to use and how to authenticate. Either `accountRef` (a cluster-scoped `CloudflareAccount`) or an inline account (`accountId` or `accountName`, plus `credentialsSecretRef`). |
| `cloudflare.accountId` | string | Cloudflare account ID. |
| `cloudflare.accountName` | string | Cloudflare account name, looked up through the API (needs Account Settings: Read). |
| `cloudflare.accountRef` | string | Name of a cluster-scoped `CloudflareAccount`. |
| `cloudflare.credentialsSecretRef` | object | Secret in the resource's namespace holding the API token. |
| `cloudflare.credentialsSecretRef.key` | string | Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`). |
| `cloudflare.credentialsSecretRef.name` | string, required |  |
| `connector` | object | The managed cloudflared Deployment. Default `{"protocol":"auto"}`. |
| `connector.extraArgs` | []string | Extra arguments passed to `cloudflared tunnel` before `run`, e.g. `--edge-ip-version=6`. |
| `connector.image` | string | Official `cloudflare/cloudflared` image, pinned tag or digest. Defaults to the operator's configured image. |
| `connector.nodeSelector` | map[string]string |  |
| `connector.protocol` | string | One of `auto`, `quic`, `http2`. Default `auto`. |
| `connector.replicas` | integer | Defaults to the operator's configured default (2). |
| `connector.resources` | object | ResourceRequirements describes the compute resource requirements. |
| `connector.resources.claims` | []object | Claims lists the names of resources, defined in spec.resourceClaims, that are used by this container. This is an alpha field and requires enabling the DynamicResourceAllocation feature gate. This field is immutable. It can only be set for containers. |
| `connector.resources.claims[].name` | string, required | Name must match the name of one entry in pod.spec.resourceClaims of the Pod where this field is used. It makes that resource available inside a container. |
| `connector.resources.claims[].request` | string | Request is the name chosen for a request in the referenced claim. If empty, everything from the claim is made available, otherwise only the result of this request. |
| `connector.resources.limits` | map[string]int-or-string | Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| `connector.resources.requests` | map[string]int-or-string | Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. Requests cannot exceed Limits. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| `connector.tolerations` | []object |  |
| `connector.tolerations[].effect` | string | Effect indicates the taint effect to match. Empty means match all taint effects. When specified, allowed values are NoSchedule, PreferNoSchedule and NoExecute. |
| `connector.tolerations[].key` | string | Key is the taint key that the toleration applies to. Empty means match all taint keys. If the key is empty, operator must be Exists; this combination means to match all values and all keys. |
| `connector.tolerations[].operator` | string | Operator represents a key's relationship to the value. Valid operators are Exists and Equal. Defaults to Equal. Exists is equivalent to wildcard for value, so that a pod can tolerate all taints of a particular category. |
| `connector.tolerations[].tolerationSeconds` | integer | TolerationSeconds represents the period of time the toleration (which must be of effect NoExecute, otherwise this field is ignored) tolerates the taint. By default, it is not set, which means tolerate the taint forever (do not evict). Zero and negative values will be treated as 0 (evict immediately) by the system. |
| `connector.tolerations[].value` | string | Value is the taint value the toleration matches to. If the operator is Exists, the value should be empty, otherwise just a regular string. |
| `deletionPolicy` | string | One of `Delete`, `Retain`. Default `Delete`. |
| `fallback` | object | What unmatched requests get. Defaults to `{status: 404}`. |
| `fallback.service` | string |  |
| `fallback.status` | integer |  |
| `name` | string | Cloudflare tunnel name. Defaults to `<namespace>-<name>-<clusterId[:8]>`. Immutable. |
| `originDefaults` | object | Origin settings applied to every route unless the route overrides them. |
| `originDefaults.caPoolSecretRef` | object | CA bundle (PEM) used to verify origin certificates; mounted into the cloudflared pods. Key defaults to `ca.crt`. |
| `originDefaults.caPoolSecretRef.key` | string | Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`). |
| `originDefaults.caPoolSecretRef.name` | string, required |  |
| `originDefaults.connectTimeout` | string | Go-style duration, whole seconds (e.g. `30s`). |
| `originDefaults.disableChunkedEncoding` | boolean |  |
| `originDefaults.http2Origin` | boolean |  |
| `originDefaults.keepAliveConnections` | integer |  |
| `originDefaults.keepAliveTimeout` | string |  |
| `originDefaults.noHappyEyeballs` | boolean |  |
| `originDefaults.noTLSVerify` | boolean |  |
| `originDefaults.tlsTimeout` | string |  |

### status

| Field | Type | Description |
|---|---|---|
| `accountId` | string | Account the tunnel lives in (resolved from the spec). |
| `cname` | string | `<tunnelId>.cfargotunnel.com`, the target of route DNS records. |
| `conditions` | []object |  |
| `configHash` | string | Hash of the last applied rendered configuration. |
| `configVersion` | integer | Cloudflare's configuration version last applied. |
| `connectors` | integer | Active connector connections as reported by Cloudflare. |
| `dnsZoneIds` | []string | Zones in which this tunnel has DNS records (for cleanup). |
| `observedGeneration` | integer |  |
| `routes` | integer | Routes included in the applied configuration. |
| `tunnelId` | string |  |
| `tunnelName` | string |  |

## TunnelRoute

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `tr`.

### spec

One public hostname (and optionally a path) mapped to an origin.

| Field | Type | Description |
|---|---|---|
| `access` | object |  |
| `access.applicationRefs` | []object | AccessApplications protecting this route; `AccessReady` reflects their readiness. |
| `access.applicationRefs[].name` | string, required |  |
| `access.applicationRefs[].namespace` | string | Defaults to the referring resource's namespace. |
| `dns` | object | Default `{"adopt":false,"enabled":true}`. |
| `dns.adopt` | boolean | Take over an existing record that isn't marked as owned by this route. Default `false`. |
| `dns.enabled` | boolean | Create the proxied CNAME to the tunnel (default true). Default `true`. |
| `dns.zone` | string | Zone to create the record in. Default: the longest zone suffix the token can see. |
| `hostname` | string, required | Public hostname; `*.example.com` for a wildcard. |
| `origin` | object | Overrides for `Tunnel.spec.originDefaults`. |
| `origin.connectTimeout` | string |  |
| `origin.disableChunkedEncoding` | boolean |  |
| `origin.http2` | boolean | HTTP/2 to the origin. |
| `origin.httpHostHeader` | string |  |
| `origin.keepAliveTimeout` | string |  |
| `origin.noHappyEyeballs` | boolean |  |
| `origin.noTLSVerify` | boolean |  |
| `origin.protocol` | string | Scheme used for `backendRef` (default `http`). One of `http`, `https`, `null`. |
| `origin.serverName` | string | SNI and the name the origin certificate is verified against. |
| `path` | string | Cloudflare ingress path (a regular expression matched against the request path). Empty means the whole host. |
| `service` | object, required | Where requests go: exactly one of `backendRef`, `url` or `status`. |
| `service.backendRef` | object | A Kubernetes Service port. |
| `service.backendRef.name` | string, required |  |
| `service.backendRef.namespace` | string | Defaults to the route's namespace. Another namespace needs a grant there. |
| `service.backendRef.port` | integer, required |  |
| `service.status` | integer | A fixed HTTP status (`http_status:<code>`). |
| `service.url` | string | Any URL cloudflared can reach, e.g. `https://192.0.2.10:443`. |
| `tunnelRef` | object, required | The Tunnel to publish on. Another namespace needs a RouteGrant/ReferenceGrant there. |
| `tunnelRef.name` | string, required |  |
| `tunnelRef.namespace` | string | Defaults to the referring resource's namespace. |

### status

| Field | Type | Description |
|---|---|---|
| `conditions` | []object |  |
| `dnsRecordId` | string |  |
| `observedGeneration` | integer |  |
| `service` | string | Origin service rendered into the tunnel configuration. |
| `tunnelId` | string |  |
| `url` | string |  |
| `zoneId` | string |  |

## AccessPolicy

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `apol`.

### spec

A reusable Cloudflare Access policy (account level).

| Field | Type | Description |
|---|---|---|
| `cloudflare` | object, required | Which Cloudflare account to use and how to authenticate. Either `accountRef` (a cluster-scoped `CloudflareAccount`) or an inline account (`accountId` or `accountName`, plus `credentialsSecretRef`). |
| `cloudflare.accountId` | string | Cloudflare account ID. |
| `cloudflare.accountName` | string | Cloudflare account name, looked up through the API (needs Account Settings: Read). |
| `cloudflare.accountRef` | string | Name of a cluster-scoped `CloudflareAccount`. |
| `cloudflare.credentialsSecretRef` | object | Secret in the resource's namespace holding the API token. |
| `cloudflare.credentialsSecretRef.key` | string | Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`). |
| `cloudflare.credentialsSecretRef.name` | string, required |  |
| `decision` | string, required | One of `allow`, `deny`, `bypass`, `non_identity`. |
| `exclude` | []object | None of these rules may match. |
| `exclude[].anyValidServiceToken` | boolean |  |
| `exclude[].emailDomains` | []string |  |
| `exclude[].emails` | []string |  |
| `exclude[].everyone` | boolean |  |
| `exclude[].groups` | []string | Access group IDs. |
| `exclude[].ipRanges` | []string | CIDRs. |
| `exclude[].loginMethods` | []string | Identity provider IDs. |
| `exclude[].serviceTokens` | []object | `AccessServiceToken` resources. |
| `exclude[].serviceTokens[].name` | string, required |  |
| `exclude[].serviceTokens[].namespace` | string | Defaults to the referring resource's namespace. |
| `include` | []object, required | Any of these rules must match. |
| `include[].anyValidServiceToken` | boolean |  |
| `include[].emailDomains` | []string |  |
| `include[].emails` | []string |  |
| `include[].everyone` | boolean |  |
| `include[].groups` | []string | Access group IDs. |
| `include[].ipRanges` | []string | CIDRs. |
| `include[].loginMethods` | []string | Identity provider IDs. |
| `include[].serviceTokens` | []object | `AccessServiceToken` resources. |
| `include[].serviceTokens[].name` | string, required |  |
| `include[].serviceTokens[].namespace` | string | Defaults to the referring resource's namespace. |
| `name` | string | Name shown in Cloudflare (an ownership suffix is appended). Defaults to `<namespace>/<name>`. |
| `require` | []object | All of these rules must match. |
| `require[].anyValidServiceToken` | boolean |  |
| `require[].emailDomains` | []string |  |
| `require[].emails` | []string |  |
| `require[].everyone` | boolean |  |
| `require[].groups` | []string | Access group IDs. |
| `require[].ipRanges` | []string | CIDRs. |
| `require[].loginMethods` | []string | Identity provider IDs. |
| `require[].serviceTokens` | []object | `AccessServiceToken` resources. |
| `require[].serviceTokens[].name` | string, required |  |
| `require[].serviceTokens[].namespace` | string | Defaults to the referring resource's namespace. |
| `sessionDuration` | string |  |

### status

| Field | Type | Description |
|---|---|---|
| `accountId` | string |  |
| `conditions` | []object |  |
| `observedGeneration` | integer |  |
| `policyId` | string |  |

## AccessApplication

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `aapp`.

### spec

A `self_hosted` Cloudflare Access application covering one or more destinations.

| Field | Type | Description |
|---|---|---|
| `allowedIdps` | []string | Identity provider IDs; empty means all configured. |
| `appLauncherVisible` | boolean | Default `false`. |
| `cloudflare` | object, required | Which Cloudflare account to use and how to authenticate. Either `accountRef` (a cluster-scoped `CloudflareAccount`) or an inline account (`accountId` or `accountName`, plus `credentialsSecretRef`). |
| `cloudflare.accountId` | string | Cloudflare account ID. |
| `cloudflare.accountName` | string | Cloudflare account name, looked up through the API (needs Account Settings: Read). |
| `cloudflare.accountRef` | string | Name of a cluster-scoped `CloudflareAccount`. |
| `cloudflare.credentialsSecretRef` | object | Secret in the resource's namespace holding the API token. |
| `cloudflare.credentialsSecretRef.key` | string | Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`). |
| `cloudflare.credentialsSecretRef.name` | string, required |  |
| `destinations` | []string, required | `host` or `host/path` destinations. |
| `name` | string | Name shown in Cloudflare (an ownership suffix is appended). Defaults to `<namespace>/<name>`. |
| `options` | object | Passthrough for less common Cloudflare application fields (camelCase or snake_case). |
| `policies` | []object | Reusable `AccessPolicy` resources, in precedence order. |
| `policies[].name` | string, required |  |
| `policies[].namespace` | string | Defaults to the referring resource's namespace. |
| `sessionDuration` | string |  |

### status

| Field | Type | Description |
|---|---|---|
| `accountId` | string |  |
| `applicationId` | string |  |
| `aud` | string | Application audience tag (for validating Access JWTs at the origin). |
| `conditions` | []object |  |
| `observedGeneration` | integer |  |

## AccessServiceToken

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `ast`.

### spec

A Cloudflare Access service token; the credentials are written to a Secret.

| Field | Type | Description |
|---|---|---|
| `cloudflare` | object, required | Which Cloudflare account to use and how to authenticate. Either `accountRef` (a cluster-scoped `CloudflareAccount`) or an inline account (`accountId` or `accountName`, plus `credentialsSecretRef`). |
| `cloudflare.accountId` | string | Cloudflare account ID. |
| `cloudflare.accountName` | string | Cloudflare account name, looked up through the API (needs Account Settings: Read). |
| `cloudflare.accountRef` | string | Name of a cluster-scoped `CloudflareAccount`. |
| `cloudflare.credentialsSecretRef` | object | Secret in the resource's namespace holding the API token. |
| `cloudflare.credentialsSecretRef.key` | string | Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`). |
| `cloudflare.credentialsSecretRef.name` | string, required |  |
| `duration` | string | Default `8760h`. |
| `name` | string |  |
| `secretName` | string, required | Secret receiving `CF-Access-Client-Id` and `CF-Access-Client-Secret`. |

### status

| Field | Type | Description |
|---|---|---|
| `accountId` | string |  |
| `clientId` | string |  |
| `conditions` | []object |  |
| `expiresAt` | string |  |
| `observedGeneration` | integer |  |
| `tokenId` | string |  |

## RouteGrant

`tunnelgate.geeko.me/v1alpha1`, namespaced, short names: `rg`.

### spec

Same shape and semantics as Gateway API's `ReferenceGrant`, for clusters without it: lives in
the namespace of the referenced objects (`to`) and permits references from `from`.

| Field | Type | Description |
|---|---|---|
| `from` | []object, required |  |
| `from[].group` | string, required | API group; `""` for the core group. |
| `from[].kind` | string, required |  |
| `from[].namespace` | string, required |  |
| `to` | []object, required |  |
| `to[].group` | string, required |  |
| `to[].kind` | string, required |  |
| `to[].name` | string | A specific object; omitted means all objects of the kind. |
