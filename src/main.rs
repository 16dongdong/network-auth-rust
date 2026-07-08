use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use network_auth_rust::{
    config::AppConfig,
    deploy::{
        OwnerSpec, ProjectPreflightOptions, parse_release_keep, prepare_release_storage,
        prune_releases,
    },
    http::{self, AppState},
    install::{
        IdStrategy, SchemaMigrationPlan, run_schema_migration, runtime_schema_patch_check_count,
    },
    repository::{AuthRepository, CardQuery, connect_database},
    service::{
        admin::AdminService,
        admin_session::AdminSessionService,
        client::ClientService,
        login::{LoginService, prewarm_slider_images},
        remote_api::RemoteApiService,
    },
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(name = "network-auth-rust")]
#[command(about = "ACE network auth Rust backend")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long, default_value = "config/local.php")]
        config: String,
        #[arg(long, default_value = "public")]
        public_root: PathBuf,
        #[arg(long, default_value = "resources/install/schema.sql")]
        schema: PathBuf,
        #[arg(long, default_value = "storage/cache/install.lock")]
        install_lock: PathBuf,
    },
    Preflight {
        #[arg(long, default_value = "config/local.php")]
        config: String,
        #[arg(long)]
        database: bool,
        #[arg(long)]
        strict: bool,
        #[arg(long, default_value = "public")]
        public_root: PathBuf,
        #[arg(long, default_value = "resources/install/schema.sql")]
        schema: PathBuf,
        #[arg(long, default_value = "storage")]
        storage_root: PathBuf,
    },
    Migrate {
        #[arg(long, default_value = "config/local.php")]
        config: String,
        #[arg(long, default_value = "resources/install/schema.sql")]
        schema: PathBuf,
        #[arg(long, default_value = "auto_increment")]
        id_strategy: String,
        #[arg(long)]
        dry_run: bool,
    },
    PrewarmSliderImages {
        #[arg(long, default_value = "public")]
        public_root: PathBuf,
        #[arg(long)]
        force: bool,
    },
    PrepareReleaseStorage {
        #[arg(long, default_value = "/var/www/ace-network-auth")]
        base: PathBuf,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    PruneReleases {
        #[arg(long, default_value = "/var/www/ace-network-auth")]
        base: PathBuf,
        #[arg(long, default_value = "3")]
        keep: String,
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command.unwrap_or(Command::Serve {
        listen: "127.0.0.1:8080".parse()?,
        config: "config/local.php".to_string(),
        public_root: PathBuf::from("public"),
        schema: PathBuf::from("resources/install/schema.sql"),
        install_lock: PathBuf::from("storage/cache/install.lock"),
    }) {
        Command::Serve {
            listen,
            config,
            public_root,
            schema,
            install_lock,
        } => serve(listen, &config, public_root, schema, install_lock).await?,
        Command::Preflight {
            config,
            database,
            strict,
            public_root,
            schema,
            storage_root,
        } => preflight(&config, database, strict, public_root, schema, storage_root).await?,
        Command::Migrate {
            config,
            schema,
            id_strategy,
            dry_run,
        } => migrate(&config, &schema, &id_strategy, dry_run).await?,
        Command::PrewarmSliderImages { public_root, force } => {
            prewarm_slider_images_command(&public_root, force).await?
        }
        Command::PrepareReleaseStorage {
            base,
            owner,
            dry_run,
        } => prepare_release_storage_command(&base, owner.as_deref(), dry_run)?,
        Command::PruneReleases {
            base,
            keep,
            dry_run,
        } => prune_releases_command(&base, &keep, dry_run)?,
    }

    Ok(())
}

async fn serve(
    listen: SocketAddr,
    config_path: &str,
    public_root: PathBuf,
    schema_path: PathBuf,
    install_lock_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::from_php_file(config_path)?;
    config.validate()?;
    let pool = connect_database(&config.database).await?;
    let repository = AuthRepository::new(pool);
    let system_key = config.system_key.clone();
    let state = AppState::new(
        repository.clone(),
        AdminSessionService::new(
            repository.clone(),
            system_key.clone(),
            config.admin_token_hash.clone(),
        ),
        AdminService::new(repository.clone(), system_key.clone()),
        ClientService::new(repository.clone(), system_key.clone()),
        LoginService::new(repository.clone(), system_key.clone()),
        RemoteApiService::new(repository, system_key.clone()),
        system_key,
        public_root,
        PathBuf::from(config_path),
        schema_path,
        install_lock_path,
        config.demo_mode,
    );
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "network auth rust backend listening");
    axum::serve(
        listener,
        http::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C shutdown handler");
        }
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
            }
        };

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    tracing::info!("shutdown signal received");
}

async fn preflight(
    config_path: &str,
    check_database: bool,
    strict: bool,
    public_root: PathBuf,
    schema_path: PathBuf,
    storage_root: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = network_auth_rust::deploy::run_project_preflight(&ProjectPreflightOptions {
        config_path: PathBuf::from(config_path),
        public_root,
        schema_path,
        storage_root,
        strict,
    });
    for warning in &report.warnings {
        println!("WARNING: {warning}");
    }
    if !report.failures.is_empty() {
        for failure in &report.failures {
            println!("FAIL: {failure}");
        }
        return Err(format!("Preflight failed: {} issue(s)", report.failures.len()).into());
    }

    let config = AppConfig::from_php_file(config_path)?;
    config.validate()?;
    if check_database {
        let pool = connect_database(&config.database).await?;
        let repository = AuthRepository::new(pool);
        repository.get_site_settings().await?;
        repository.admin_overview(None).await?;
        let apps = repository.list_apps(1, 0).await?;
        if let Some(app) = apps.first() {
            let query = CardQuery {
                status: String::new(),
                duration_category: String::new(),
                keyword: String::new(),
                card_hash: String::new(),
                search_token_hashes: Vec::new(),
                limit: 1,
                offset: 0,
            };
            repository.count_cards(app.id, &query).await?;
            repository
                .list_cards(app.id, app.heartbeat_enabled == 1, &query)
                .await?;
            repository.find_remote_config(app.id).await?;
        }
        println!("Database preflight passed.");
        return Ok(());
    }
    println!("Preflight passed.");
    Ok(())
}

async fn migrate(
    config_path: &str,
    schema_path: &PathBuf,
    id_strategy: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let strategy = parse_id_strategy(id_strategy)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let plan = SchemaMigrationPlan::from_file(schema_path, strategy)?;
    if dry_run {
        println!(
            "Schema migration dry run passed: {} statements, {} runtime patch checks, id_strategy={}.",
            plan.statement_count(),
            runtime_schema_patch_check_count(),
            id_strategy_name(plan.id_strategy())
        );
        return Ok(());
    }

    let config = AppConfig::from_php_file(config_path)?;
    config.validate()?;
    let pool = connect_database(&config.database).await?;
    let result = run_schema_migration(
        &pool,
        &plan,
        &config.database.database_name,
        Some(&config.system_key),
    )
    .await?;
    println!(
        "Schema migration applied: {} statements, {} runtime patches, id_strategy={}.",
        result.schema_statements,
        result.runtime_patches,
        id_strategy_name(plan.id_strategy())
    );
    Ok(())
}

async fn prewarm_slider_images_command(
    public_root: &PathBuf,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = prewarm_slider_images(public_root, force).await?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn prepare_release_storage_command(
    base: &PathBuf,
    owner: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner = owner.map(OwnerSpec::parse).transpose()?;
    let result = prepare_release_storage(base, owner.as_ref(), dry_run)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn prune_releases_command(
    base: &PathBuf,
    keep: &str,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let keep = parse_release_keep(keep)?;
    let result = prune_releases(base, keep, dry_run)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn parse_id_strategy(value: &str) -> Result<IdStrategy, String> {
    match value {
        "auto_increment" | "auto-increment" => Ok(IdStrategy::AutoIncrement),
        "uuid_short_default" | "uuid-short-default" => Ok(IdStrategy::UuidShortDefault),
        _ => Err("id_strategy 必须是 auto_increment 或 uuid_short_default".to_string()),
    }
}

fn id_strategy_name(strategy: IdStrategy) -> &'static str {
    match strategy {
        IdStrategy::AutoIncrement => "auto_increment",
        IdStrategy::UuidShortDefault => "uuid_short_default",
    }
}
