//! Bulk import endpoints for administrative data loading.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::warn;
use trueid_common::model::{source_from_str, IdentityEvent};

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

const MAX_IMPORT_EVENTS: usize = 10_000;

/// Bulk event import request payload.
#[derive(Debug, Deserialize)]
pub(crate) struct ImportEventsRequest {
    events: Vec<ImportEvent>,
}

/// Single event item for import payload.
#[derive(Debug, Deserialize)]
struct ImportEvent {
    ip: String,
    user: String,
    mac: Option<String>,
    source: Option<String>,
    timestamp: Option<String>,
}

/// Bulk event import response payload.
#[derive(Debug, Serialize)]
struct ImportEventsResponse {
    imported: i64,
    skipped: i64,
    errors: Vec<String>,
}

/// Imports up to 10k identity events in one request.
///
/// Parameters: `auth` - authenticated admin principal, `state` - app state, `body` - import payload.
/// Returns: import summary with imported/skipped/errors counters.
pub(crate) async fn import_events(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<ImportEventsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.events.len() > MAX_IMPORT_EVENTS {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Maximum 10000 events per request",
        )
        .with_request_id(&auth.request_id));
    }

    let db = helpers::require_db(&state, &auth.request_id)?;
    let mut imported = 0_i64;
    let mut skipped = 0_i64;
    let mut errors: Vec<String> = Vec::new();

    for (idx, event) in body.events.into_iter().enumerate() {
        let row_no = idx + 1;
        let ip: IpAddr = match event.ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                skipped += 1;
                errors.push(format!("row {row_no}: invalid IP '{}'", event.ip));
                continue;
            }
        };
        if event.user.trim().is_empty() {
            skipped += 1;
            errors.push(format!("row {row_no}: user must not be empty"));
            continue;
        }
        let timestamp = match parse_optional_timestamp(event.timestamp.as_deref()) {
            Ok(ts) => ts,
            Err(msg) => {
                skipped += 1;
                errors.push(format!("row {row_no}: {msg}"));
                continue;
            }
        };
        let source = source_from_str(event.source.as_deref().unwrap_or("Manual"));
        let identity_event = IdentityEvent {
            source,
            ip,
            user: event.user.trim().to_string(),
            timestamp,
            raw_data: format!("bulk_import row={row_no}"),
            mac: event
                .mac
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty()),
            confidence_score: 100,
        };
        if let Err(e) = db.upsert_mapping(identity_event, None).await {
            skipped += 1;
            warn!(error = %e, row = row_no, "Bulk import upsert failed");
            errors.push(format!("row {row_no}: database upsert failed"));
            continue;
        }
        imported += 1;
    }

    helpers::audit(
        db,
        &auth,
        "import_events_bulk",
        None,
        Some(&format!(
            "imported={}, skipped={}, errors={}",
            imported,
            skipped,
            errors.len()
        )),
    )
    .await;

    Ok(Json(ImportEventsResponse {
        imported,
        skipped,
        errors,
    }))
}

/// Parses optional RFC3339 timestamp; defaults to current UTC.
///
/// Parameters: `raw` - optional timestamp string.
/// Returns: parsed timestamp or current UTC.
fn parse_optional_timestamp(raw: Option<&str>) -> Result<DateTime<Utc>, String> {
    let Some(raw) = raw else {
        return Ok(Utc::now());
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| format!("invalid timestamp '{raw}'"))
}
