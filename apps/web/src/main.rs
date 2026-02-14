//! TrueID Web binary — startup and server binding.

use anyhow::Result;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use trueid_common::model::UserRole;
use trueid_common::{env_or_default, parse_socket_addr};
use trueid_web::{
    auth::JwtConfig, build_router, helpers, rate_limit, AppState, DEFAULT_ENGINE_URL,
};

const DEFAULT_DB_URL: &str = "sqlite://net-identity.db?mode=rwc";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_ASSETS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

/// Waits for Ctrl+C and logs graceful shutdown message.
///
/// Parameters: none.
/// Returns: completes when shutdown signal is received.
async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    info!("Web server shutting down...");
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // ── Production startup validation ──────────────────────
    let dev_mode = std::env::var("TRUEID_DEV_MODE")
        .map(|v| v == "true")
        .unwrap_or(false);

    if dev_mode {
        warn!("DEV MODE ENABLED — relaxed security. Do NOT use in production.");
    } else {
        let jwt = std::env::var("JWT_SECRET").unwrap_or_default();
        if jwt.len() < 32 {
            error!("FATAL: JWT_SECRET must be set and at least 32 chars in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        let est = std::env::var("ENGINE_SERVICE_TOKEN").unwrap_or_default();
        if est.len() < 32 {
            error!("FATAL: ENGINE_SERVICE_TOKEN must be set and at least 32 chars in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        let cek = std::env::var("CONFIG_ENCRYPTION_KEY").unwrap_or_default();
        if cek.len() != 64 || !cek.chars().all(|c| c.is_ascii_hexdigit()) {
            error!("FATAL: CONFIG_ENCRYPTION_KEY must be 64 hex chars (32 bytes) in production. Set TRUEID_DEV_MODE=true to bypass.");
            std::process::exit(1);
        }
        info!("Production mode: all required secrets verified.");
    }

    let db_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            warn!("DATABASE_URL not set — using default: {}", DEFAULT_DB_URL);
            DEFAULT_DB_URL.to_string()
        }
    };
    let http_addr = parse_socket_addr(
        &env_or_default("HTTP_BIND", DEFAULT_HTTP_ADDR),
        DEFAULT_HTTP_ADDR,
    )?;
    let engine_url = env_or_default("ENGINE_API_URL", DEFAULT_ENGINE_URL);

    info!(db_url = %db_url, "Initializing database (read-only dashboard)");
    let db = match trueid_common::db::init_db(&db_url).await {
        Ok(d) => {
            info!("Database connected successfully");

            // ── Admin bootstrap ──────────────────────────────
            match d.count_users().await {
                Ok(0) => {
                    let admin_user = std::env::var("TRUEID_ADMIN_USER").unwrap_or_default();
                    let admin_pass = std::env::var("TRUEID_ADMIN_PASS").unwrap_or_default();
                    if !admin_user.is_empty() && !admin_pass.is_empty() {
                        if admin_pass.len() < 12 {
                            error!("FATAL: TRUEID_ADMIN_PASS must be at least 12 characters.");
                            std::process::exit(1);
                        }
                        match d
                            .create_user(&admin_user, &admin_pass, UserRole::Admin)
                            .await
                        {
                            Ok(user) => {
                                let _ = d.set_force_password_change(user.id, true).await;
                                helpers::audit_principal(
                                    &d,
                                    Some(user.id),
                                    &admin_user,
                                    "system",
                                    "bootstrap_admin_created",
                                    None,
                                    None,
                                    None,
                                    None,
                                )
                                .await;
                                info!(
                                    "Bootstrap: Created initial admin user '{}'. Password change required on first login.",
                                    admin_user
                                );
                            }
                            Err(e) => {
                                error!("Failed to create bootstrap admin: {e:#}");
                            }
                        }
                    } else {
                        warn!(
                            "No users in database and TRUEID_ADMIN_USER/TRUEID_ADMIN_PASS not set. \
                             Authentication will be non-functional until an admin is bootstrapped."
                        );
                    }
                }
                Ok(_) => { /* normal startup, users already exist */ }
                Err(e) => warn!("Could not count users during bootstrap: {e:#}"),
            }

            Some(Arc::new(d))
        }
        Err(e) => {
            error!(
                "Database connection failed: {e:#}\n\
                 -> Check DATABASE_URL in .env\n\
                 -> Run 'cargo run -p trueid-engine' first to create tables\n\
                 -> Server will start but API will return 503"
            );
            None
        }
    };

    // ── Background: session cleanup every hour ─────────────
    if let Some(ref db_ref) = db {
        let cleanup_db = Arc::clone(db_ref);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match cleanup_db.cleanup_expired_sessions().await {
                    Ok(n) if n > 0 => info!(deleted = n, "Cleaned up expired sessions"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "Session cleanup failed"),
                }
            }
        });
    }

    let jwt_config = JwtConfig::from_env(dev_mode);

    let engine_service_token = std::env::var("ENGINE_SERVICE_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let login_limiter = Arc::new(rate_limit::RateLimiter::new(10, 60));
    let api_key_limiter = Arc::new(rate_limit::RateLimiter::new(100, 60));

    let auth_chain = db.as_ref().map(|d| {
        Arc::new(trueid_common::auth_provider::AuthProviderChain::default_chain(Arc::clone(d)))
    });
    let runtime_config = if let Some(ref db_ref) = db {
        trueid_common::app_config::AppConfig::load(db_ref.as_ref()).await
    } else {
        trueid_common::app_config::AppConfig::default()
    };

    let state = AppState {
        db,
        config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
        engine_url,
        http_client: reqwest::Client::new(),
        jwt_config,
        engine_service_token,
        login_limiter: login_limiter.clone(),
        api_key_limiter: api_key_limiter.clone(),
        auth_chain,
    };

    // ── Background: rate limiter cleanup every 5 min ─────
    {
        let ll = login_limiter;
        let al = api_key_limiter;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                ll.cleanup();
                al.cleanup();
            }
        });
    }

    let app = build_router(state).fallback_service(ServeDir::new(env_or_default(
        "ASSETS_DIR",
        DEFAULT_ASSETS_DIR,
    )));

    // ── TLS or plain TCP ──────────────────────────────────
    let tls_cert = std::env::var("TLS_CERT").ok().filter(|s| !s.is_empty());
    let tls_key = std::env::var("TLS_KEY").ok().filter(|s| !s.is_empty());

    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            info!(%http_addr, cert = %cert_path, "Starting HTTPS server (native TLS)");
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;
            let handle = axum_server::Handle::new();
            let handle_for_signal = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                handle_for_signal.graceful_shutdown(Some(std::time::Duration::from_secs(15)));
            });
            axum_server::bind_rustls(http_addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            if !dev_mode {
                warn!("TLS_CERT/TLS_KEY not set — serving plain HTTP. Use a reverse proxy with TLS in production.");
            }
            info!(%http_addr, "Starting HTTP server");
            let listener = tokio::net::TcpListener::bind(http_addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }

    info!("Web server stopped");
    Ok(())
}
