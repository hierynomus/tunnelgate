//! Condition types and reasons. These are part of the API contract (automation such as GitOps
//! tools and pipelines waits on them), so they only ever get added to, never renamed. See `docs/conditions.md`.

/// Condition types.
pub mod types {
    /// The single condition callers wait on. True when every other condition of the resource is.
    pub const READY: &str = "Ready";
    /// Tunnel: the Cloudflare tunnel exists and its ID is recorded in status.
    pub const TUNNEL_CREATED: &str = "TunnelCreated";
    /// Tunnel: Cloudflare reports at least one active connector connection.
    pub const CONNECTOR_READY: &str = "ConnectorReady";
    /// Tunnel: the rendered ingress configuration is applied in Cloudflare.
    /// TunnelRoute: the route is part of the applied configuration.
    pub const CONFIG_APPLIED: &str = "ConfigApplied";
    /// TunnelRoute: the route is valid, its references resolve and it doesn't conflict.
    pub const ACCEPTED: &str = "Accepted";
    /// TunnelRoute: the DNS record exists and points at the tunnel.
    pub const DNS_READY: &str = "DNSReady";
    /// TunnelRoute: referenced Access applications are Ready.
    pub const ACCESS_READY: &str = "AccessReady";
    /// AccessPolicy: a potentially dangerous combination was configured (informational).
    pub const WARNING: &str = "Warning";
    /// AccessServiceToken: less than 10% of the token's duration is left.
    pub const EXPIRING: &str = "Expiring";
}

/// Condition reasons (CamelCase, stable).
pub mod reasons {
    pub const RECONCILED: &str = "Reconciled";
    pub const PROGRESSING: &str = "Progressing";
    pub const CREATED: &str = "Created";
    pub const APPLIED: &str = "Applied";
    pub const PENDING: &str = "Pending";

    pub const INVALID_SPEC: &str = "InvalidSpec";
    pub const CREDENTIALS_NOT_FOUND: &str = "CredentialsNotFound";
    pub const ACCOUNT_NOT_FOUND: &str = "AccountNotFound";
    pub const ACCOUNT_NOT_ALLOWED: &str = "AccountNotAllowed";
    pub const CLOUDFLARE_ERROR: &str = "CloudflareError";
    pub const CLOUDFLARE_UNAUTHORIZED: &str = "CloudflareUnauthorized";

    pub const CA_POOL_NOT_FOUND: &str = "CAPoolNotFound";
    pub const NO_CONNECTIONS: &str = "NoConnections";
    pub const CONNECTED: &str = "Connected";

    pub const TUNNEL_NOT_FOUND: &str = "TunnelNotFound";
    pub const TUNNEL_NOT_READY: &str = "TunnelNotReady";
    pub const BACKEND_NOT_FOUND: &str = "BackendNotFound";
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    pub const CONFLICT: &str = "Conflict";
    pub const CONFIG_LIMIT: &str = "ConfigLimit";
    pub const ZONE_NOT_FOUND: &str = "ZoneNotFound";
    pub const DNS_DISABLED: &str = "DNSDisabled";
    pub const RECORD_READY: &str = "RecordReady";

    pub const NOT_REQUESTED: &str = "NotRequested";
    pub const APPLICATION_NOT_FOUND: &str = "ApplicationNotFound";
    pub const APPLICATION_NOT_READY: &str = "ApplicationNotReady";
    pub const POLICY_NOT_FOUND: &str = "PolicyNotFound";
    pub const POLICY_NOT_READY: &str = "PolicyNotReady";
    pub const SERVICE_TOKEN_NOT_FOUND: &str = "ServiceTokenNotFound";
    pub const SERVICE_TOKEN_NOT_READY: &str = "ServiceTokenNotReady";
    pub const ALLOW_EVERYONE: &str = "AllowEveryone";
    pub const SECRET_LOST_ROTATED: &str = "SecretLostRotated";
    pub const EXPIRES_SOON: &str = "ExpiresSoon";
    pub const NOT_EXPIRING: &str = "NotExpiring";
    pub const EXPIRED: &str = "Expired";
    pub const VERIFIED: &str = "Verified";
}
