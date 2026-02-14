//! TrueID command-line client for API-driven operations.

use clap::{Parser, Subcommand, ValueEnum};
use std::process::ExitCode;

mod client;
mod commands;

/// CLI root options and selected command.
#[derive(Parser)]
#[command(name = "trueid", about = "TrueID Identity Correlation Engine CLI")]
#[command(version, long_about = None)]
struct Cli {
    /// TrueID server URL.
    #[arg(
        long,
        env = "TRUEID_URL",
        default_value = "http://localhost:3000",
        global = true
    )]
    url: String,

    /// API key for authentication.
    #[arg(long, env = "TRUEID_API_KEY", global = true)]
    api_key: Option<String>,

    /// Output format.
    #[arg(long, default_value = "table", value_enum, global = true)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Output format for CLI data rendering.
#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

/// Top-level CLI commands.
#[derive(Subcommand)]
enum Commands {
    /// Look up an IP address.
    Lookup {
        /// IP address to look up.
        ip: String,
    },
    /// Search mappings and events.
    Search {
        /// Search query text.
        query: String,
        /// Exact IP filter.
        #[arg(long)]
        ip: Option<String>,
        /// Exact user filter.
        #[arg(long)]
        user: Option<String>,
        /// Exact MAC filter.
        #[arg(long)]
        mac: Option<String>,
        /// Source filter.
        #[arg(long)]
        source: Option<String>,
        /// Max rows.
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Mapping management.
    Mappings {
        #[command(subcommand)]
        cmd: MappingsCmd,
    },
    /// Conflict management.
    Conflicts {
        #[command(subcommand)]
        cmd: ConflictsCmd,
    },
    /// Alert management.
    Alerts {
        #[command(subcommand)]
        cmd: AlertsCmd,
    },
    /// System status and adapters.
    Status,
    /// Summary statistics.
    Stats,
    /// User management (admin).
    Users {
        #[command(subcommand)]
        cmd: UsersCmd,
    },
    /// Export data.
    Export {
        #[command(subcommand)]
        cmd: ExportCmd,
    },
    /// Import data.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
    /// Retention management.
    Retention {
        #[command(subcommand)]
        cmd: RetentionCmd,
    },
    /// Service health check.
    Health,
}

/// Mappings subcommands.
#[derive(Subcommand)]
enum MappingsCmd {
    /// List mappings.
    List {
        /// Filter by active mappings only.
        #[arg(long)]
        active: bool,
        /// Filter by source.
        #[arg(long)]
        source: Option<String>,
        /// Max rows.
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Count mappings.
    Count,
    /// Delete mapping by IP.
    Delete {
        /// Mapping IP.
        ip: String,
    },
    /// Submit manual mapping.
    Submit {
        /// Mapping IP.
        #[arg(long)]
        ip: String,
        /// Username.
        #[arg(long)]
        user: String,
        /// Optional MAC.
        #[arg(long)]
        mac: Option<String>,
    },
}

/// Conflicts subcommands.
#[derive(Subcommand)]
enum ConflictsCmd {
    /// List conflicts.
    List {
        /// Show unresolved conflicts only.
        #[arg(long)]
        unresolved: bool,
        /// Max rows.
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Show conflict stats.
    Stats,
    /// Resolve conflict by id.
    Resolve {
        /// Conflict id.
        id: i64,
        /// Optional note.
        #[arg(long)]
        note: Option<String>,
    },
}

/// Alerts subcommands.
#[derive(Subcommand)]
enum AlertsCmd {
    /// List alert rules.
    Rules,
    /// List alert history.
    History {
        /// Optional severity filter.
        #[arg(long)]
        severity: Option<String>,
        /// Max rows.
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Show alert stats.
    Stats,
}

/// Users subcommands.
#[derive(Subcommand)]
enum UsersCmd {
    /// List users.
    List,
    /// Create user.
    Create {
        /// Username.
        #[arg(long)]
        username: String,
        /// Password.
        #[arg(long)]
        password: String,
        /// Role (Admin, Operator, Viewer).
        #[arg(long)]
        role: String,
    },
    /// Delete user.
    Delete {
        /// User id.
        id: i64,
    },
}

/// Export subcommands.
#[derive(Subcommand)]
enum ExportCmd {
    /// Export mappings.
    Mappings {
        /// Export format.
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Export events.
    Events {
        /// Export format.
        #[arg(long, default_value = "json")]
        format: String,
        /// Lookback in days.
        #[arg(long, default_value = "7")]
        days: i64,
    },
}

/// Import subcommands.
#[derive(Subcommand)]
enum ImportCmd {
    /// Bulk-import events from CSV or JSON.
    Events {
        /// Input file path.
        #[arg(long)]
        file: String,
    },
}

/// Retention subcommands.
#[derive(Subcommand)]
enum RetentionCmd {
    /// List retention policies.
    List,
    /// Update policy retention in days.
    Set {
        /// Policy table name.
        table: String,
        /// Retention days.
        #[arg(long)]
        days: i64,
        /// Enable policy.
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// Force retention run.
    Run,
}

/// Runs CLI and maps failures to POSIX exit codes.
///
/// Exit code mapping: `0` success, `1` generic error, `2` authentication error.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::run(cli).await {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("error: {err}");
            if err.is_auth() {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}
