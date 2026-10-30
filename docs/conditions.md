# Conditions

Every resource has `status.conditions`, `status.observedGeneration` and a `Ready` condition —
the one thing callers wait on (`kubectl wait --for=condition=Ready`). Types and reasons are an API
contract: they are only ever added, never renamed (`tunnelgate_api::conditions`). When `Ready` is
False, its reason and message are copied from the first failing condition, prefixed with that
condition's type.

## Tunnel

| Type | True when | False reasons |
|---|---|---|
| `TunnelCreated` | the Cloudflare tunnel exists and its ID is in `status.tunnelId` | `CredentialsNotFound`, `AccountNotFound`, `AccountNotAllowed`, `InvalidSpec`, `Conflict` (a tunnel with that name exists and isn't ours), `CloudflareUnauthorized`, `CloudflareError` |
| `ConnectorReady` | Cloudflare reports ≥1 active connection | `NoConnections`, `CAPoolNotFound`, `CloudflareError` |
| `ConfigApplied` | the rendered configuration is applied (`status.configVersion`) | `InvalidSpec`, `CloudflareUnauthorized`, `CloudflareError` |
| `Ready` | all of the above | first failing reason |

## TunnelRoute

| Type | True when | False reasons |
|---|---|---|
| `Accepted` | references resolve and the route doesn't conflict | `TunnelNotFound`, `RefNotPermitted`, `BackendNotFound`, `Conflict`, `ConfigLimit`, `ZoneNotFound`, `InvalidSpec` |
| `ConfigApplied` | the route is in the applied tunnel configuration | `TunnelNotReady`, `TunnelNotFound`, the `Accepted` reason, `CloudflareError` |
| `DNSReady` | the proxied CNAME points at the tunnel (`DNSDisabled` when `dns.enabled: false`) | `Conflict` (a record we don't own; set `dns.adopt`), `Pending`, `TunnelNotReady`, `CloudflareError` |
| `AccessReady` | every referenced `AccessApplication` is Ready (`NotRequested` without refs) | `ApplicationNotFound`, `ApplicationNotReady` |
| `Ready` | all of the above **and** the tunnel has an active connector | first failing reason, or `TunnelNotReady` |

## AccessPolicy

| Type | True when | False reasons |
|---|---|---|
| `Ready` | the reusable policy exists in Cloudflare with the rendered rules (`status.policyId`) | `CredentialsNotFound`, `AccountNotFound`, `AccountNotAllowed`, `InvalidSpec`, `ServiceTokenNotFound`, `ServiceTokenNotReady`, `Conflict` (the policy lost its ownership suffix), `CloudflareUnauthorized`, `CloudflareError`, `Pending` (being deleted while applications still use it) |
| `Warning` | informational, doesn't affect `Ready`; only present when it applies | `AllowEveryone` (`allow` + `everyone` without `require`) |

## AccessApplication

| Type | True when | False reasons |
|---|---|---|
| `Ready` | the `self_hosted` app exists with these destinations and policies, in order (`status.applicationId`, `status.aud`) | credentials reasons as above, `InvalidSpec`, `PolicyNotFound`, `PolicyNotReady` (also: policy in another account), `Conflict`, `CloudflareUnauthorized`, `CloudflareError` |

## AccessServiceToken

| Type | True when | False reasons |
|---|---|---|
| `Ready` | the token exists and its credentials are in `spec.secretName` (`CF-Access-Client-Id`, `CF-Access-Client-Secret`). Reason `SecretLostRotated` while the current token replaced one whose Secret was lost | credentials reasons as above, `InvalidSpec`, `Conflict` (the Secret exists and isn't ours, or the token lost its suffix), `Expired`, `CloudflareUnauthorized`, `CloudflareError` |
| `Expiring` | less than 10% of the token's duration is left (`ExpiresSoon`; `Expired` once past). False: `NotExpiring` | |

Delete the Secret to rotate a token by hand: a new token is created and the Secret rewritten.
Policies that include the token follow its new ID, and then the old token is deleted (Cloudflare
refuses while a policy still includes it). Deleting an `AccessServiceToken` that policies still
include waits (`Ready=False, reason=Pending`, naming them).

## CloudflareAccount

| Type | True when | False reasons |
|---|---|---|
| `Ready` | the token reads the account's zones (`Verified`, `status.accountId`) | `CredentialsNotFound`, `InvalidSpec`, `AccountNotFound`, `CloudflareUnauthorized`, `CloudflareError` |

## Gateway API

GatewayClass, Gateway and HTTPRoute use the Gateway API conditions; see
[gateway-api.md](gateway-api.md#status) for the reasons tunnelgate sets.
