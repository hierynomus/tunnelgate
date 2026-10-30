use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use tunnelgate_cf::{ClientConfig, RateLimit};
use tunnelgate_operator::context::{DEFAULT_CONNECTOR_IMAGE, HttpFactory, Settings};
use tunnelgate_operator::leader::{self, LeaseConfig};

#[derive(Debug, Parser)]
#[command(name = "tunnelgate-operator", version = tunnelgate_cf::VERSION, about = "Publishes services through Cloudflare Tunnel")]
struct Args {
    /// Full resync period (drift repair), e.g. 10m.
    #[arg(long, env = "TUNNELGATE_RESYNC", default_value = "10m")]
    resync: String,
    /// cloudflared image used when a Tunnel doesn't set one.
    #[arg(long, env = "TUNNELGATE_CONNECTOR_IMAGE", default_value = DEFAULT_CONNECTOR_IMAGE)]
    connector_image: String,
    /// Connector replicas when a Tunnel doesn't set them.
    #[arg(long, env = "TUNNELGATE_CONNECTOR_REPLICAS", default_value_t = 2)]
    connector_replicas: i32,
    /// Cloudflare API base URL (for tests).
    #[arg(long, env = "TUNNELGATE_CLOUDFLARE_API", default_value = tunnelgate_cf::DEFAULT_BASE_URL)]
    cloudflare_api: String,
    /// Average Cloudflare API requests per second per token; 0 disables the client-side limit.
    #[arg(long, env = "TUNNELGATE_CLOUDFLARE_RATE", default_value_t = 3.0)]
    cloudflare_rate: f64,
    /// Requests that may be sent at once before the average applies.
    #[arg(long, env = "TUNNELGATE_CLOUDFLARE_BURST", default_value_t = 100)]
    cloudflare_burst: u32,
    /// Log format: json or text.
    #[arg(long, env = "TUNNELGATE_LOG_FORMAT", default_value = "json")]
    log_format: String,
    /// Disable leader election (single replica, local development).
    #[arg(long, env = "TUNNELGATE_NO_LEADER_ELECTION")]
    no_leader_election: bool,
    /// Namespace of the leader election Lease; defaults to the pod's namespace.
    #[arg(long, env = "POD_NAMESPACE", default_value = "tunnelgate")]
    lease_namespace: String,
    /// Identity for leader election; defaults to the pod name.
    #[arg(long, env = "POD_NAME")]
    identity: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(&args.log_format);

    let resync = tunnelgate_render::duration::parse_millis(&args.resync).map_err(anyhow::Error::msg)?;
    let settings = Settings {
        resync: Duration::from_millis(resync),
        default_connector_image: args.connector_image,
        default_connector_replicas: args.connector_replicas,
        ..Default::default()
    };

    let client = kube::Client::try_default().await.context("connecting to Kubernetes")?;
    let cluster_id = tunnelgate_operator::cluster_id(&client).await.context("reading the cluster ID")?;

    if !args.no_leader_election {
        let identity = args.identity.unwrap_or_else(|| format!("tunnelgate-{}", std::process::id()));
        leader::acquire(
            client.clone(),
            LeaseConfig {
                namespace: args.lease_namespace,
                name: "tunnelgate-operator".to_owned(),
                identity,
                lease_duration: Duration::from_secs(15),
                renew_interval: Duration::from_secs(5),
            },
        )
        .await?;
    }

    let rate_limit = (args.cloudflare_rate > 0.0)
        .then(|| RateLimit { per_second: args.cloudflare_rate, burst: args.cloudflare_burst.max(1) });
    let factory =
        HttpFactory { config: ClientConfig { base_url: args.cloudflare_api, rate_limit, ..Default::default() } };
    tunnelgate_operator::run(client, settings, cluster_id, Arc::new(factory)).await
}

fn init_tracing(format: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,kube=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if format == "text" {
        builder.init();
    } else {
        builder.json().flatten_event(true).init();
    }
}
