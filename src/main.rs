use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use clap::Parser;

use handlers::{root, AegisState};
use std::sync::Arc;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;


use config::AegisConfig;
use tokio::sync::Mutex;
use tokio::time;

mod clients;
mod config;
mod handlers;
// mod logging;

const DEFAULT_CONFIG_PATH: &str = "config.yaml";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config_file: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Parse CLI args
    let args = Args::parse();

    // Fetch config
    let config: AegisConfig = AegisConfig::from_file(&args.config_file).unwrap();
    config.validate().unwrap();

    // Init logger
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NONE)
        .with_target(true);

    let filter = EnvFilter::new("info,actix_server=error");

    tracing_subscriber::registry()
        .with(config.server.log_level.into_level_filter())
        .with(filter)
        .with(fmt_layer)
        .init();

    // Init Redis client
    let redis_client: Option<clients::redis::RedisClient>;
    if config.redis.enabled {
        redis_client = Some(
            clients::redis::RedisClient::new(config.redis.url.clone())
                .await
                .unwrap(),
        );
        tracing::info!("🔌 Connected to redis");
    } else {
        tracing::warn!("Redis is disabled");
        redis_client = None
    }

    // Init http client
    let http_client = reqwest::Client::new();

    let listen_address = config.server.address.clone();
    let listen_port = config.server.port;

    // Init AegisState
    let state: AegisState = AegisState {
        config: Arc::new(Mutex::new(config)),
        redis_client,
        http_client,
    };

    // Watch config file for changes every 5 seconds
    tokio::spawn(config::watch_config(args.config_file, state.config.clone()));

    // Start Aegis server
    tracing::info!(
        "🚀 Aegis listening on address {}:{}",
        listen_address,
        listen_port
    );

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new("%a %r %s %b %{Referer}i %{User-Agent}i %D"))
            // .wrap(from_fn(firewall_middleware))
            .app_data(Data::new(state.clone()))
            .default_service(web::to(root))
    })
    .bind((listen_address, listen_port))?
    .client_request_timeout(time::Duration::from_secs(10))
    .run()
    .await
}
