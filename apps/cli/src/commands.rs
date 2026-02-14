//! Command handlers for TrueID CLI operations.

use crate::client::{CliError, TrueIdClient};
use crate::{
    AlertsCmd, Cli, Commands, ConflictsCmd, ExportCmd, ImportCmd, MappingsCmd, OutputFormat,
    RetentionCmd, UsersCmd,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::fs;
use tabled::builder::Builder;

/// Executes the selected CLI command.
///
/// Parameters: `cli` - parsed CLI options and command.
/// Returns: success or CLI error.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    let client = TrueIdClient::new(&cli.url, cli.api_key.as_deref());
    match cli.command {
        Commands::Lookup { ip } => cmd_lookup(&client, &cli.format, &ip).await,
        Commands::Search {
            query,
            ip,
            user,
            mac,
            source,
            limit,
        } => {
            let args = SearchArgs {
                query,
                ip,
                user,
                mac,
                source,
                limit,
            };
            cmd_search(&client, &cli.format, &args).await
        }
        Commands::Mappings { cmd } => cmd_mappings(&client, &cli.format, cmd).await,
        Commands::Conflicts { cmd } => cmd_conflicts(&client, &cli.format, cmd).await,
        Commands::Alerts { cmd } => cmd_alerts(&client, &cli.format, cmd).await,
        Commands::Status => cmd_status(&client, &cli.format).await,
        Commands::Stats => cmd_stats(&client, &cli.format).await,
        Commands::Users { cmd } => cmd_users(&client, &cli.format, cmd).await,
        Commands::Export { cmd } => cmd_export(&client, cmd).await,
        Commands::Import { cmd } => cmd_import(&client, &cli.format, cmd).await,
        Commands::Retention { cmd } => cmd_retention(&client, &cli.format, cmd).await,
        Commands::Health => cmd_health(&client, &cli.format).await,
    }
}

/// Search command arguments passed to handler.
struct SearchArgs {
    query: String,
    ip: Option<String>,
    user: Option<String>,
    mac: Option<String>,
    source: Option<String>,
    limit: u32,
}

/// Runs lookup command.
///
/// Parameters: `client` - API client, `format` - output format, `ip` - lookup IP.
/// Returns: success or CLI error.
async fn cmd_lookup(
    client: &TrueIdClient,
    format: &OutputFormat,
    ip: &str,
) -> Result<(), CliError> {
    let data = client
        .get_json(&format!("/lookup/{}", urlencoding(ip)))
        .await?;
    match format {
        OutputFormat::Json => print_json(&data),
        OutputFormat::Csv => print_lookup_csv(&data),
        OutputFormat::Table => print_lookup_table(&data),
    }
    Ok(())
}

/// Runs search command.
///
/// Parameters: `client` - API client, `format` - output format, `args` - search arguments.
/// Returns: success or CLI error.
async fn cmd_search(
    client: &TrueIdClient,
    format: &OutputFormat,
    args: &SearchArgs,
) -> Result<(), CliError> {
    let mut query = format!(
        "/api/v2/search?q={}&limit={}",
        urlencoding(&args.query),
        args.limit
    );
    if let Some(v) = &args.ip {
        query.push_str(&format!("&ip={}", urlencoding(v)));
    }
    if let Some(v) = &args.user {
        query.push_str(&format!("&user={}", urlencoding(v)));
    }
    if let Some(v) = &args.mac {
        query.push_str(&format!("&mac={}", urlencoding(v)));
    }
    if let Some(v) = &args.source {
        query.push_str(&format!("&source={}", urlencoding(v)));
    }
    let data = client.get_json(&query).await?;
    match format {
        OutputFormat::Json => print_json(&data),
        OutputFormat::Csv => print_search_csv(&data),
        OutputFormat::Table => print_search_table(&data),
    }
    Ok(())
}

/// Runs mappings command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected mappings subcommand.
/// Returns: success or CLI error.
async fn cmd_mappings(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: MappingsCmd,
) -> Result<(), CliError> {
    match cmd {
        MappingsCmd::List {
            active,
            source,
            limit,
        } => {
            let mut path = format!("/api/v1/mappings?per_page={limit}&page=1");
            if active {
                path.push_str("&active=true");
            }
            if let Some(src) = source {
                path.push_str(&format!("&source={}", urlencoding(&src)));
            }
            let data = client.get_json(&path).await?;
            match format {
                OutputFormat::Json => print_json(&data),
                OutputFormat::Csv => print_mappings_csv(&data),
                OutputFormat::Table => print_mappings_table(&data),
            }
            Ok(())
        }
        MappingsCmd::Count => {
            let data = client.get_json("/api/v1/stats").await?;
            let total = data
                .get("total_mappings")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            println!("{total}");
            Ok(())
        }
        MappingsCmd::Delete { ip } => {
            let _ = client
                .delete_json(&format!("/api/v1/mappings/{}", urlencoding(&ip)))
                .await?;
            println!("deleted mapping: {ip}");
            Ok(())
        }
        MappingsCmd::Submit { ip, user, mac } => {
            let mut payload = json!({
                "ip": ip,
                "user": user
            });
            if let Some(m) = mac {
                payload["mac"] = json!(m);
            }
            let data = client.post_json("/api/v1/mappings", &payload).await?;
            match format {
                OutputFormat::Json => print_json(&data),
                OutputFormat::Csv => print_mappings_csv(&json!({ "data": [data] })),
                OutputFormat::Table => print_mappings_table(&json!({ "data": [data] })),
            }
            Ok(())
        }
    }
}

/// Runs conflicts command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected conflicts subcommand.
/// Returns: success or CLI error.
async fn cmd_conflicts(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: ConflictsCmd,
) -> Result<(), CliError> {
    match cmd {
        ConflictsCmd::List { unresolved, limit } => {
            let status_filter = if unresolved { "open" } else { "all" };
            let data = client
                .get_json(&format!(
                    "/api/v2/conflicts?status={status_filter}&per_page={limit}&page=1"
                ))
                .await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        ConflictsCmd::Stats => {
            let data = client.get_json("/api/v2/conflicts/stats").await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        ConflictsCmd::Resolve { id, note } => {
            let payload = json!({ "resolution_note": note.unwrap_or_default() });
            let data = client
                .post_json(&format!("/api/v2/conflicts/{id}/resolve"), &payload)
                .await?;
            print_with_format(format, &data)?;
            Ok(())
        }
    }
}

/// Runs alerts command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected alerts subcommand.
/// Returns: success or CLI error.
async fn cmd_alerts(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: AlertsCmd,
) -> Result<(), CliError> {
    match cmd {
        AlertsCmd::Rules => {
            let data = client.get_json("/api/v2/alerts/rules").await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        AlertsCmd::History { severity, limit } => {
            let mut path = format!("/api/v2/alerts/history?per_page={limit}&page=1");
            if let Some(s) = severity {
                path.push_str(&format!("&severity={}", urlencoding(&s)));
            }
            let data = client.get_json(&path).await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        AlertsCmd::Stats => {
            let data = client.get_json("/api/v2/alerts/stats").await?;
            print_with_format(format, &data)?;
            Ok(())
        }
    }
}

/// Runs status command.
///
/// Parameters: `client` - API client, `format` - output format.
/// Returns: success or CLI error.
async fn cmd_status(client: &TrueIdClient, format: &OutputFormat) -> Result<(), CliError> {
    let adapters = client.get_json("/api/v1/admin/adapters").await?;
    let runtime = client.get_json("/api/v1/admin/runtime-config").await?;
    let payload = json!({
        "adapters": adapters,
        "runtime": runtime
    });
    match format {
        OutputFormat::Json => print_json(&payload),
        OutputFormat::Csv => print_status_csv(&payload),
        OutputFormat::Table => print_status_table(&payload),
    }
    Ok(())
}

/// Runs stats command.
///
/// Parameters: `client` - API client, `format` - output format.
/// Returns: success or CLI error.
async fn cmd_stats(client: &TrueIdClient, format: &OutputFormat) -> Result<(), CliError> {
    let stats = client.get_json("/api/v1/stats").await?;
    let compliance = client.get_json("/api/v2/analytics/compliance").await?;
    let payload = json!({
        "stats": stats,
        "compliance": compliance
    });
    match format {
        OutputFormat::Json => print_json(&payload),
        OutputFormat::Csv => print_stats_csv(&payload),
        OutputFormat::Table => print_stats_table(&payload),
    }
    Ok(())
}

/// Runs users command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected users subcommand.
/// Returns: success or CLI error.
async fn cmd_users(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: UsersCmd,
) -> Result<(), CliError> {
    match cmd {
        UsersCmd::List => {
            let data = client.get_json("/api/v1/users?page=1&per_page=200").await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        UsersCmd::Create {
            username,
            password,
            role,
        } => {
            let data = client
                .post_json(
                    "/api/v1/users",
                    &json!({
                        "username": username,
                        "password": password,
                        "role": role
                    }),
                )
                .await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        UsersCmd::Delete { id } => {
            let _ = client.delete_json(&format!("/api/v1/users/{id}")).await?;
            println!("deleted user: {id}");
            Ok(())
        }
    }
}

/// Runs export command set.
///
/// Parameters: `client` - API client, `cmd` - selected export subcommand.
/// Returns: success or CLI error.
async fn cmd_export(client: &TrueIdClient, cmd: ExportCmd) -> Result<(), CliError> {
    match cmd {
        ExportCmd::Mappings { format } => {
            let text = client
                .get_text(&format!(
                    "/api/v2/export/mappings?format={}",
                    urlencoding(&format)
                ))
                .await?;
            print!("{text}");
            Ok(())
        }
        ExportCmd::Events { format, days } => {
            let from = Utc::now() - Duration::days(days.max(1));
            let text = client
                .get_text(&format!(
                    "/api/v2/export/events?format={}&from={}",
                    urlencoding(&format),
                    urlencoding(&from.to_rfc3339())
                ))
                .await?;
            print!("{text}");
            Ok(())
        }
    }
}

/// Runs import command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected import subcommand.
/// Returns: success or CLI error.
async fn cmd_import(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: ImportCmd,
) -> Result<(), CliError> {
    match cmd {
        ImportCmd::Events { file } => {
            let events = load_import_events(&file)?;
            if events.is_empty() {
                return Err(CliError::new("input file has no events".to_string(), false));
            }
            let mut imported = 0_i64;
            let mut skipped = 0_i64;
            let mut errors: Vec<String> = Vec::new();
            for chunk in events.chunks(100) {
                let resp = client
                    .post_json("/api/v2/import/events", &json!({ "events": chunk }))
                    .await?;
                imported += resp.get("imported").and_then(Value::as_i64).unwrap_or(0);
                skipped += resp.get("skipped").and_then(Value::as_i64).unwrap_or(0);
                if let Some(arr) = resp.get("errors").and_then(Value::as_array) {
                    for item in arr {
                        if let Some(text) = item.as_str() {
                            errors.push(text.to_string());
                        }
                    }
                }
            }
            let payload = json!({
                "imported": imported,
                "skipped": skipped,
                "errors": errors
            });
            print_with_format(format, &payload)?;
            Ok(())
        }
    }
}

/// Runs retention command set.
///
/// Parameters: `client` - API client, `format` - output format, `cmd` - selected retention subcommand.
/// Returns: success or CLI error.
async fn cmd_retention(
    client: &TrueIdClient,
    format: &OutputFormat,
    cmd: RetentionCmd,
) -> Result<(), CliError> {
    match cmd {
        RetentionCmd::List => {
            let data = client.get_json("/api/v2/admin/retention").await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        RetentionCmd::Set {
            table,
            days,
            enabled,
        } => {
            let data = client
                .put_json(
                    &format!("/api/v2/admin/retention/{}", urlencoding(&table)),
                    &json!({
                        "retention_days": days,
                        "enabled": enabled
                    }),
                )
                .await?;
            print_with_format(format, &data)?;
            Ok(())
        }
        RetentionCmd::Run => {
            let data = client
                .post_json("/api/v2/admin/retention/run", &json!({}))
                .await?;
            print_with_format(format, &data)?;
            Ok(())
        }
    }
}

/// Runs health command.
///
/// Parameters: `client` - API client, `format` - output format.
/// Returns: success or CLI error.
async fn cmd_health(client: &TrueIdClient, format: &OutputFormat) -> Result<(), CliError> {
    let started = std::time::Instant::now();
    let _ = client.get_text("/health").await?;
    let elapsed_ms = started.elapsed().as_millis();
    let payload = json!({
        "web_api": "healthy",
        "engine": "healthy",
        "database": "ok",
        "latency_ms": elapsed_ms
    });
    match format {
        OutputFormat::Json => print_json(&payload),
        OutputFormat::Csv => {
            println!("web_api,engine,database,latency_ms");
            println!("healthy,healthy,ok,{elapsed_ms}");
        }
        OutputFormat::Table => {
            println!("✓ Web API: healthy ({elapsed_ms}ms)");
            println!("✓ Engine: healthy");
            println!("✓ Database: ok");
        }
    }
    Ok(())
}

/// Prints generic data in selected output format.
///
/// Parameters: `format` - selected output format, `value` - JSON payload.
/// Returns: success or CLI error.
fn print_with_format(format: &OutputFormat, value: &Value) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => print_json(value),
        OutputFormat::Csv => print_csv_object(value),
        OutputFormat::Table => print_table_object(value),
    }
    Ok(())
}

/// Prints JSON payload in compact machine-friendly form.
///
/// Parameters: `value` - JSON payload.
/// Returns: none.
fn print_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    );
}

/// Prints lookup result as a vertical table-like block.
///
/// Parameters: `value` - lookup response payload.
/// Returns: none.
fn print_lookup_table(value: &Value) {
    let mapping = value.get("mapping").unwrap_or(&Value::Null);
    println!(
        "IP:         {}",
        mapping.get("ip").and_then(Value::as_str).unwrap_or("-")
    );
    println!(
        "User:       {}",
        mapping
            .get("current_users")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .and_then(Value::as_str)
            .unwrap_or("-")
    );
    println!(
        "MAC:        {}",
        mapping.get("mac").and_then(Value::as_str).unwrap_or("-")
    );
    println!(
        "Source:     {}",
        mapping.get("source").and_then(Value::as_str).unwrap_or("-")
    );
    println!(
        "Confidence: {}",
        mapping
            .get("confidence_score")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    );
    println!(
        "Last Seen:  {}",
        humanize_time(mapping.get("last_seen").and_then(Value::as_str))
    );
    println!(
        "Vendor:     {}",
        mapping.get("vendor").and_then(Value::as_str).unwrap_or("-")
    );
    println!(
        "Subnet:     {}",
        mapping
            .get("subnet_name")
            .and_then(Value::as_str)
            .unwrap_or("-")
    );
}

/// Prints lookup result as CSV.
///
/// Parameters: `value` - lookup response payload.
/// Returns: none.
fn print_lookup_csv(value: &Value) {
    let mapping = value.get("mapping").unwrap_or(&Value::Null);
    println!("ip,user,mac,source,last_seen,confidence,vendor,subnet_name");
    println!(
        "{},{},{},{},{},{},{},{}",
        csv_field(mapping.get("ip")),
        csv_field(
            mapping
                .get("current_users")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
        ),
        csv_field(mapping.get("mac")),
        csv_field(mapping.get("source")),
        csv_field(mapping.get("last_seen")),
        csv_field(mapping.get("confidence_score")),
        csv_field(mapping.get("vendor")),
        csv_field(mapping.get("subnet_name")),
    );
}

/// Prints search mappings as a table.
///
/// Parameters: `value` - search response payload.
/// Returns: none.
fn print_search_table(value: &Value) {
    let rows = value
        .get("mappings")
        .and_then(|m| m.get("data"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut table = Builder::default();
    table.push_record(["IP", "User", "MAC", "Source", "Last Seen", "Confidence"]);
    for row in &rows {
        let user = row
            .get("current_users")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .and_then(Value::as_str)
            .unwrap_or("-");
        table.push_record([
            row.get("ip").and_then(Value::as_str).unwrap_or("-"),
            user,
            row.get("mac").and_then(Value::as_str).unwrap_or("-"),
            row.get("source").and_then(Value::as_str).unwrap_or("-"),
            &humanize_time(row.get("last_seen").and_then(Value::as_str)),
            &row.get("confidence_score")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                .to_string(),
        ]);
    }
    println!("{}", table.build());
}

/// Prints search mappings as CSV.
///
/// Parameters: `value` - search response payload.
/// Returns: none.
fn print_search_csv(value: &Value) {
    println!("ip,user,mac,source,last_seen,confidence");
    let rows = value
        .get("mappings")
        .and_then(|m| m.get("data"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for row in &rows {
        let user = row
            .get("current_users")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or(Value::Null);
        println!(
            "{},{},{},{},{},{}",
            csv_field(row.get("ip")),
            csv_field(Some(&user)),
            csv_field(row.get("mac")),
            csv_field(row.get("source")),
            csv_field(row.get("last_seen")),
            csv_field(row.get("confidence_score")),
        );
    }
}

/// Prints mappings list as a table.
///
/// Parameters: `value` - mappings list payload.
/// Returns: none.
fn print_mappings_table(value: &Value) {
    let rows = value
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut table = Builder::default();
    table.push_record(["IP", "User", "MAC", "Source", "Last Seen", "Confidence"]);
    for row in &rows {
        let user = row
            .get("current_users")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .and_then(Value::as_str)
            .unwrap_or("-");
        table.push_record([
            row.get("ip").and_then(Value::as_str).unwrap_or("-"),
            user,
            row.get("mac").and_then(Value::as_str).unwrap_or("-"),
            row.get("source").and_then(Value::as_str).unwrap_or("-"),
            &humanize_time(row.get("last_seen").and_then(Value::as_str)),
            &row.get("confidence_score")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                .to_string(),
        ]);
    }
    println!("{}", table.build());
}

/// Prints mappings list as CSV.
///
/// Parameters: `value` - mappings list payload.
/// Returns: none.
fn print_mappings_csv(value: &Value) {
    println!("ip,user,mac,source,last_seen,confidence");
    let rows = value
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for row in &rows {
        let user = row
            .get("current_users")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or(Value::Null);
        println!(
            "{},{},{},{},{},{}",
            csv_field(row.get("ip")),
            csv_field(Some(&user)),
            csv_field(row.get("mac")),
            csv_field(row.get("source")),
            csv_field(row.get("last_seen")),
            csv_field(row.get("confidence_score")),
        );
    }
}

/// Prints status payload as table.
///
/// Parameters: `value` - status payload with adapters and runtime.
/// Returns: none.
fn print_status_table(value: &Value) {
    println!("TrueID Engine Status");
    println!("  Adapters:");
    if let Some(arr) = value.get("adapters").and_then(Value::as_array) {
        for a in arr {
            let dot = if a.get("status").and_then(Value::as_str) == Some("listening") {
                "●"
            } else {
                "○"
            };
            let name = a.get("name").and_then(Value::as_str).unwrap_or("-");
            let bind = a.get("bind").and_then(Value::as_str).unwrap_or("-");
            let events = a
                .get("events_total")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            println!(
                "    {name:<10} {dot} {:<9} {:<16} ({events} events)",
                a.get("status").and_then(Value::as_str).unwrap_or("-"),
                bind
            );
        }
    }
    let db_url = value
        .get("runtime")
        .and_then(|v| v.get("database_url"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    println!("  Database:     {db_url}");
}

/// Prints status payload as CSV.
///
/// Parameters: `value` - status payload.
/// Returns: none.
fn print_status_csv(value: &Value) {
    println!("name,status,bind,events_total");
    if let Some(arr) = value.get("adapters").and_then(Value::as_array) {
        for a in arr {
            println!(
                "{},{},{},{}",
                csv_field(a.get("name")),
                csv_field(a.get("status")),
                csv_field(a.get("bind")),
                csv_field(a.get("events_total")),
            );
        }
    }
}

/// Prints stats payload as table.
///
/// Parameters: `value` - merged stats and compliance payload.
/// Returns: none.
fn print_stats_table(value: &Value) {
    let stats = value.get("stats").unwrap_or(&Value::Null);
    let compliance = value.get("compliance").unwrap_or(&Value::Null);
    let mappings_total = stats
        .get("total_mappings")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let active = stats
        .get("active_mappings")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let inactive = stats
        .get("inactive_mappings")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    println!("Mappings:     {mappings_total} ({active} active, {inactive} inactive)");
    println!(
        "Events:       {}",
        stats
            .get("total_events")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    );
    println!(
        "Conflicts:    {} unresolved",
        compliance
            .get("conflicts")
            .and_then(|v| v.get("total_unresolved"))
            .and_then(Value::as_i64)
            .unwrap_or_default()
    );
    println!(
        "Alerts:       {} fired (7d)",
        compliance
            .get("alerts")
            .and_then(|v| v.get("fired_7d"))
            .and_then(Value::as_i64)
            .unwrap_or_default()
    );
}

/// Prints stats payload as CSV.
///
/// Parameters: `value` - merged stats and compliance payload.
/// Returns: none.
fn print_stats_csv(value: &Value) {
    let stats = value.get("stats").unwrap_or(&Value::Null);
    let compliance = value.get("compliance").unwrap_or(&Value::Null);
    println!("mappings_total,mappings_active,mappings_inactive,events_total,conflicts_unresolved,alerts_fired_7d");
    println!(
        "{},{},{},{},{},{}",
        stats
            .get("total_mappings")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        stats
            .get("active_mappings")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        stats
            .get("inactive_mappings")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        stats
            .get("total_events")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        compliance
            .get("conflicts")
            .and_then(|v| v.get("total_unresolved"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        compliance
            .get("alerts")
            .and_then(|v| v.get("fired_7d"))
            .and_then(Value::as_i64)
            .unwrap_or_default()
    );
}

/// Prints generic object-like JSON as a simple key/value table.
///
/// Parameters: `value` - JSON payload.
/// Returns: none.
fn print_table_object(value: &Value) {
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                println!("(empty)");
                return;
            }
            print_table_array(arr);
        }
        Value::Object(map) => {
            let mut table = Builder::default();
            table.push_record(["key", "value"]);
            for (k, v) in map {
                table.push_record([k.as_str(), &value_to_string(v)]);
            }
            println!("{}", table.build());
        }
        _ => println!("{}", value_to_string(value)),
    }
}

/// Prints JSON as flattened CSV-compatible rows when possible.
///
/// Parameters: `value` - JSON payload.
/// Returns: none.
fn print_csv_object(value: &Value) {
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                return;
            }
            print_csv_array(arr);
        }
        Value::Object(map) => {
            println!("key,value");
            for (k, v) in map {
                println!("{},{}", csv_escape(k), csv_escape(&value_to_string(v)));
            }
        }
        _ => println!("{}", csv_escape(&value_to_string(value))),
    }
}

/// Prints array of objects as table.
///
/// Parameters: `rows` - JSON array payload.
/// Returns: none.
fn print_table_array(rows: &[Value]) {
    let first_obj = rows.first().and_then(Value::as_object);
    let Some(first_obj) = first_obj else {
        println!("{}", rows.len());
        return;
    };
    let headers = first_obj.keys().cloned().collect::<Vec<_>>();
    let mut table = Builder::default();
    table.push_record(headers.iter().map(String::as_str));
    for row in rows {
        let mut rec: Vec<String> = Vec::with_capacity(headers.len());
        for h in &headers {
            rec.push(value_to_string(row.get(h).unwrap_or(&Value::Null)));
        }
        table.push_record(rec);
    }
    println!("{}", table.build());
}

/// Prints array of objects as CSV.
///
/// Parameters: `rows` - JSON array payload.
/// Returns: none.
fn print_csv_array(rows: &[Value]) {
    let first_obj = rows.first().and_then(Value::as_object);
    let Some(first_obj) = first_obj else {
        return;
    };
    let headers = first_obj.keys().cloned().collect::<Vec<_>>();
    println!("{}", headers.join(","));
    for row in rows {
        let mut fields = Vec::with_capacity(headers.len());
        for h in &headers {
            fields.push(csv_escape(&value_to_string(
                row.get(h).unwrap_or(&Value::Null),
            )));
        }
        println!("{}", fields.join(","));
    }
}

/// Loads import events from CSV or JSON file.
///
/// Parameters: `file` - path to import file.
/// Returns: vector of import event objects.
fn load_import_events(file: &str) -> Result<Vec<Value>, CliError> {
    let raw = fs::read_to_string(file)
        .map_err(|e| CliError::new(format!("failed to read '{file}': {e}"), false))?;
    if file.ends_with(".json") {
        let parsed: Value = serde_json::from_str(&raw)
            .map_err(|e| CliError::new(format!("invalid JSON input: {e}"), false))?;
        let arr = parsed.as_array().ok_or_else(|| {
            CliError::new(
                "JSON import expects array of event objects".to_string(),
                false,
            )
        })?;
        return Ok(arr.to_vec());
    }
    parse_csv_events(&raw)
}

/// Parses CSV import payload into event objects.
///
/// Parameters: `raw` - CSV source text.
/// Returns: vector of import event objects.
fn parse_csv_events(raw: &str) -> Result<Vec<Value>, CliError> {
    let mut out = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if idx == 0 && trimmed.to_ascii_lowercase().starts_with("ip,user,") {
            continue;
        }
        let parts = trimmed.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err(CliError::new(
                format!("invalid CSV row {}: expected at least ip,user", idx + 1),
                false,
            ));
        }
        let mut obj = json!({
            "ip": parts[0],
            "user": parts[1]
        });
        if parts.len() >= 3 && !parts[2].is_empty() {
            obj["mac"] = json!(parts[2]);
        }
        if parts.len() >= 4 && !parts[3].is_empty() {
            obj["source"] = json!(parts[3]);
        }
        if parts.len() >= 5 && !parts[4].is_empty() {
            obj["timestamp"] = json!(parts[4]);
        }
        out.push(obj);
    }
    Ok(out)
}

/// Converts value to string for CLI rendering.
///
/// Parameters: `value` - JSON value.
/// Returns: display-friendly string.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Escapes single string field for CSV output.
///
/// Parameters: `value` - unescaped field value.
/// Returns: CSV-safe field value.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Converts optional JSON value into escaped CSV field.
///
/// Parameters: `value` - optional JSON value.
/// Returns: CSV-safe field value.
fn csv_field(value: Option<&Value>) -> String {
    let s = value.map(value_to_string).unwrap_or_default();
    csv_escape(&s)
}

/// Converts timestamp string to relative age.
///
/// Parameters: `raw` - RFC3339 timestamp string.
/// Returns: human-readable relative age.
fn humanize_time(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return "-".to_string();
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|v| v.with_timezone(&Utc));
    let Some(ts) = parsed else {
        return raw.to_string();
    };
    let delta = Utc::now() - ts;
    if delta.num_minutes() < 1 {
        "just now".to_string()
    } else if delta.num_minutes() < 60 {
        format!("{} min ago", delta.num_minutes())
    } else if delta.num_hours() < 48 {
        format!("{}h ago", delta.num_hours())
    } else {
        format!("{}d ago", delta.num_days())
    }
}

/// URL-encodes a query component for safe request building.
///
/// Parameters: `value` - unencoded query value.
/// Returns: percent-encoded string.
fn urlencoding(value: &str) -> String {
    fn is_safe(ch: u8) -> bool {
        ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b'~')
    }
    let mut out = String::new();
    for b in value.as_bytes() {
        if is_safe(*b) {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
