# Cloudflare API token permissions

Create an **account API token** (Manage Account → Account API Tokens) scoped to one account and
the zone(s) that host your hostnames. The permissions below are verified by the live and end-to-end
tests.

Account tokens are preferred over user tokens (My Profile → API Tokens), which also work:

- They belong to the account, not a person, so they keep working when whoever created them leaves
  the account or loses access, which suits a long-running operator.
- They start with `cfat_`, which secret scanners (e.g. GitHub's) recognise if one leaks.
- Every service tunnelgate uses supports them (Tunnel, DNS, Access, zone and account management).
  tunnelgate only calls account and zone endpoints, never user endpoints such as
  `/user/tokens/verify`.
- Creating one needs Super Administrator or the API Token Provisioning permission, and can only
  grant permissions the creator has.

Never use a global API key. Give the token an expiry date where your rotation process allows it.
With `accountName` instead of `accountId`, the operator looks the account up via `GET /accounts`,
which also works with account tokens (it returns the owning account).

| Scope | Permission | Used for |
|---|---|---|
| Account | Cloudflare One Connector: cloudflared: Edit | create/delete tunnels, connector token, configuration, connections |
| Account | Access: Apps and Policies: Edit | `AccessApplication`, `AccessPolicy` |
| Account | Access: Service Tokens: Edit | `AccessServiceToken` |
| Account | Account Settings: Read | only when resources use `accountName` instead of `accountId` |
| Zone | Zone: Read | zone lookup (which zone a hostname belongs to) |
| Zone | DNS: Edit | proxied CNAMEs to `<tunnelId>.cfargotunnel.com` |

The account-token permission picker has no *Cloudflare Tunnel* group; the tunnel endpoints accept
*Cloudflare One Connector: cloudflared: Edit* (or the broader *Cloudflare One Connectors: Edit*).
User API tokens may use *Cloudflare Tunnel: Edit* instead. The zone permissions only apply to the
zones listed under the token's **Zone Resources**: include every zone tunnelgate publishes hostnames
in (or all zones of the account). A missing permission or zone shows up as HTTP 403 with code 10000
("Authentication error").

Store it in a Secret under the key `CLOUDFLARE_API_TOKEN`:

```sh
kubectl -n tunnelgate create secret generic cloudflare-api --from-literal=CLOUDFLARE_API_TOKEN=…
```

A token missing a permission shows up as `reason: CloudflareUnauthorized` on the affected
resource's condition, with the failing call in the message.

`tunnelgate sweep` needs the same token (read permissions for `--dry-run`).
