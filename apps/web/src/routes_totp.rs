//! TOTP 2FA setup, verification, and backup-code endpoints.

use axum::{http::StatusCode, response::IntoResponse, Json};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use totp_rs::{Secret, TOTP};
use tracing::warn;

use crate::error::{self, ApiError};
use crate::helpers;
use crate::middleware::AuthUser;
use crate::AppState;

/// TOTP setup response payload.
#[derive(Debug, Serialize)]
struct TotpSetupResponse {
    secret: String,
    qr_code: String,
    otpauth_url: String,
}

/// TOTP verification request payload.
#[derive(Debug, Deserialize)]
pub(crate) struct TotpVerifyRequest {
    code: String,
}

/// TOTP status response.
#[derive(Debug, Serialize)]
struct TotpStatusResponse {
    enabled: bool,
    verified_at: Option<String>,
}

/// Backup code generation response payload.
#[derive(Debug, Serialize)]
struct BackupCodesResponse {
    backup_codes: Vec<String>,
}

/// Generates a new TOTP secret and QR payload for current user.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: secret, otpauth url and base64 qr image.
pub(crate) async fn setup(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    if auth.principal_type != "user" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error::FORBIDDEN,
            "TOTP setup requires user session authentication",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let user = db
        .get_user_by_id(auth.user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
                .with_request_id(&auth.request_id)
        })?;

    let generated = Secret::generate();
    let secret_encoded = generated.to_base32();
    let totp = build_totp(&secret_encoded, &user.username).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            &format!("Failed to build TOTP secret: {e}"),
        )
        .with_request_id(&auth.request_id)
    })?;
    let qr_base64 = totp.get_qr_base64().map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            &format!("Failed to generate QR code: {e}"),
        )
        .with_request_id(&auth.request_id)
    })?;
    let secret_enc = db.encrypt_config_value(&secret_encoded).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            &format!("Encryption key missing or invalid: {e}"),
        )
        .with_request_id(&auth.request_id)
    })?;
    db.set_user_totp_secret_enc(auth.user_id, &secret_enc)
        .await
        .map_err(|e| {
            warn!(error = %e, user_id = auth.user_id, "Failed to store TOTP setup secret");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to store TOTP setup",
            )
            .with_request_id(&auth.request_id)
        })?;

    helpers::audit(
        db,
        &auth,
        "totp_setup_started",
        Some(&format!("user:{}", auth.user_id)),
        None,
    )
    .await;
    Ok(Json(TotpSetupResponse {
        secret: secret_encoded,
        qr_code: format!("data:image/png;base64,{qr_base64}"),
        otpauth_url: totp.get_url(),
    }))
}

/// Verifies TOTP code and enables 2FA.
///
/// Parameters: `auth` - authenticated user, `state` - app state, `body` - code payload.
/// Returns: generated backup codes after successful verification.
pub(crate) async fn verify(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<TotpVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if auth.principal_type != "user" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error::FORBIDDEN,
            "TOTP verification requires user session authentication",
        )
        .with_request_id(&auth.request_id));
    }
    let db = helpers::require_db(&state, &auth.request_id)?;
    let secret_enc = db
        .get_user_totp_secret_enc(auth.user_id)
        .await
        .map_err(|e| {
            warn!(error = %e, user_id = auth.user_id, "Failed to load TOTP setup secret");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to verify TOTP code",
            )
            .with_request_id(&auth.request_id)
        })?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                error::INVALID_INPUT,
                "TOTP setup not initialized",
            )
            .with_request_id(&auth.request_id)
        })?;
    let secret = db.decrypt_config_value(&secret_enc).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to decrypt TOTP secret",
        )
        .with_request_id(&auth.request_id)
    })?;
    let username = db
        .get_user_by_id(auth.user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_else(|| auth.username.clone());
    let ok = match totp_matched_timestep(&secret, &username, &body.code) {
        Some(timestep) => db
            .check_and_set_totp_timestep(auth.user_id, timestep)
            .await
            .unwrap_or(false),
        None => false,
    };
    if !ok {
        let _ = db.record_failed_login(&username).await;
        helpers::audit_system(
            db,
            &username,
            "totp_verify_failed",
            None,
            None,
            None,
            Some(&auth.request_id),
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error::INVALID_CREDENTIALS,
            "Invalid 2FA code",
        )
        .with_request_id(&auth.request_id));
    }

    let backup_codes = generate_backup_codes();
    let backup_codes_enc = db
        .encrypt_config_value(&serde_json::to_string(&backup_codes).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to encode backup codes",
            )
            .with_request_id(&auth.request_id)
        })?)
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to encrypt backup codes",
            )
            .with_request_id(&auth.request_id)
        })?;
    db.enable_user_totp(auth.user_id, &backup_codes_enc)
        .await
        .map_err(|e| {
            warn!(error = %e, user_id = auth.user_id, "Failed to enable TOTP");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to enable TOTP",
            )
            .with_request_id(&auth.request_id)
        })?;
    helpers::audit(
        db,
        &auth,
        "totp_enabled",
        Some(&format!("user:{}", auth.user_id)),
        None,
    )
    .await;
    Ok(Json(BackupCodesResponse { backup_codes }))
}

/// Returns current TOTP status for authenticated user.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: enabled flag and verification timestamp.
pub(crate) async fn status(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let user = db
        .get_user_by_id(auth.user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
                .with_request_id(&auth.request_id)
        })?;
    Ok(Json(TotpStatusResponse {
        enabled: user.totp_enabled,
        verified_at: user.totp_verified_at.map(|v| v.to_rfc3339()),
    }))
}

/// Disables TOTP for current user after code verification.
///
/// Parameters: `auth` - authenticated user, `state` - app state, `body` - code payload.
/// Returns: HTTP 200 when disabled.
pub(crate) async fn disable(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<TotpVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let user = db
        .get_user_by_id(auth.user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
                .with_request_id(&auth.request_id)
        })?;
    if !user.totp_enabled {
        return Ok(StatusCode::OK);
    }
    if !verify_user_totp_or_backup(db, &user, &body.code).await {
        let _ = db.record_failed_login(&user.username).await;
        helpers::audit(
            db,
            &auth,
            "totp_disable_failed",
            Some(&format!("user:{}", auth.user_id)),
            None,
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error::INVALID_CREDENTIALS,
            "Invalid 2FA code",
        )
        .with_request_id(&auth.request_id));
    }
    db.disable_user_totp(auth.user_id).await.map_err(|e| {
        warn!(error = %e, user_id = auth.user_id, "Failed to disable TOTP");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to disable TOTP",
        )
        .with_request_id(&auth.request_id)
    })?;
    helpers::audit(
        db,
        &auth,
        "totp_disabled",
        Some(&format!("user:{}", auth.user_id)),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

/// Regenerates backup codes for an already enabled TOTP user.
///
/// Parameters: `auth` - authenticated user, `state` - app state.
/// Returns: newly generated backup codes.
pub(crate) async fn regenerate_backup_codes(
    auth: AuthUser,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let db = helpers::require_db(&state, &auth.request_id)?;
    let user = db
        .get_user_by_id(auth.user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, error::NOT_FOUND, "User not found")
                .with_request_id(&auth.request_id)
        })?;
    if !user.totp_enabled {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            error::INVALID_INPUT,
            "Enable TOTP before generating backup codes",
        )
        .with_request_id(&auth.request_id));
    }
    let codes = generate_backup_codes();
    let codes_json = serde_json::to_string(&codes).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to encode backup codes",
        )
        .with_request_id(&auth.request_id)
    })?;
    let enc = db.encrypt_config_value(&codes_json).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error::INTERNAL_ERROR,
            "Failed to encrypt backup codes",
        )
        .with_request_id(&auth.request_id)
    })?;
    db.set_user_totp_backup_codes_enc(auth.user_id, Some(&enc))
        .await
        .map_err(|e| {
            warn!(
                error = %e,
                user_id = auth.user_id,
                "Failed to persist regenerated backup codes"
            );
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error::INTERNAL_ERROR,
                "Failed to store backup codes",
            )
            .with_request_id(&auth.request_id)
        })?;
    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}

/// Verifies provided code against user TOTP secret and one-time backup codes.
///
/// Enforces RFC 6238 §5.2 replay protection: a TOTP code is accepted only for
/// a timestep newer than the last accepted one (atomic compare-and-set).
///
/// Parameters: `db` - database handle, `user` - user record, `code` - submitted code.
/// Returns: `true` when code is valid and fresh.
pub(crate) async fn verify_user_totp_or_backup(
    db: &trueid_common::db::Db,
    user: &trueid_common::model::User,
    code: &str,
) -> bool {
    if !user.totp_enabled {
        return false;
    }
    if let Ok(Some(secret_enc)) = db.get_user_totp_secret_enc(user.id).await {
        if let Ok(secret) = db.decrypt_config_value(&secret_enc) {
            if let Some(timestep) = totp_matched_timestep(&secret, &user.username, code) {
                if let Ok(true) = db.check_and_set_totp_timestep(user.id, timestep).await {
                    return true;
                }
                warn!(user_id = user.id, timestep, "Rejected replayed TOTP code");
            }
        }
    }
    consume_backup_code(db, user.id, code).await
}

/// Builds a TOTP instance from base32 secret and username.
///
/// Parameters: `secret_base32` - base32 secret, `username` - account name.
/// Returns: configured TOTP object.
fn build_totp(secret_base32: &str, username: &str) -> anyhow::Result<TOTP> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|e| anyhow::anyhow!("invalid secret: {e}"))?;
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("TrueID".to_string()))
        .with_account_name(username.to_string())
        .build()
        .map_err(|e| anyhow::anyhow!("invalid TOTP parameters: {e}"))
}

/// Verifies one TOTP code for given secret and returns the matched timestep.
///
/// Equivalent to `check_current` with ±1 step skew, but returns the matched
/// 30-second timestep so callers can enforce replay protection, and uses a
/// constant-time comparison.
///
/// Parameters: `secret_base32` - encoded secret, `username` - account label, `code` - user code.
/// Returns: matched timestep when the code is valid.
pub(crate) fn totp_matched_timestep(
    secret_base32: &str,
    username: &str,
    code: &str,
) -> Option<i64> {
    let clean = code.trim().replace(' ', "");
    if clean.len() != 6 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let totp = build_totp(secret_base32, username).ok()?;
    let now_step = chrono::Utc::now().timestamp().div_euclid(30);
    for delta in -1i64..=1 {
        let step = now_step + delta;
        if step < 0 {
            continue;
        }
        let candidate = totp.generate((step * 30) as u64).to_string();
        if trueid_common::constant_time_eq(candidate.as_bytes(), clean.as_bytes()) {
            return Some(step);
        }
    }
    None
}

/// Generates 10 random one-time backup codes.
///
/// Returns: vector of codes in `XXXX-XXXX` format.
fn generate_backup_codes() -> Vec<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    let mut out = Vec::with_capacity(10);
    for _ in 0..10 {
        let left: String = (0..4)
            .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
            .collect();
        let right: String = (0..4)
            .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
            .collect();
        out.push(format!("{left}-{right}"));
    }
    out
}

/// Tries to consume one backup code atomically by replacing backup list.
///
/// Parameters: `db` - database handle, `user_id` - user id, `input` - provided code.
/// Returns: true when backup code was accepted and consumed.
async fn consume_backup_code(db: &trueid_common::db::Db, user_id: i64, input: &str) -> bool {
    let normalized = input.trim().to_ascii_uppercase().replace(' ', "");
    if normalized.is_empty() {
        return false;
    }
    let Some(enc) = db
        .get_user_totp_backup_codes_enc(user_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    let decoded = match db.decrypt_config_value(&enc) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut codes: Vec<String> = serde_json::from_str(&decoded).unwrap_or_default();
    let before = codes.len();
    codes.retain(|c| c.to_ascii_uppercase().replace(' ', "") != normalized);
    if codes.len() == before {
        return false;
    }
    let new_enc = match serde_json::to_string(&codes)
        .ok()
        .and_then(|json| db.encrypt_config_value(&json).ok())
    {
        Some(v) => v,
        None => return false,
    };
    // Compare-and-swap prevents two concurrent requests from consuming the
    // same one-time code (read-modify-write race).
    db.cas_user_totp_backup_codes_enc(user_id, Some(&enc), Some(&new_enc))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> String {
        // RFC 6238 test vector secret (base32 of "12345678901234567890").
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()
    }

    #[test]
    fn matched_timestep_accepts_current_code() {
        let secret = test_secret();
        let totp = build_totp(&secret, "alice").unwrap();
        let code = totp.generate_current().to_string();
        let step = chrono::Utc::now().timestamp().div_euclid(30);
        let matched = totp_matched_timestep(&secret, "alice", &code);
        assert!(matched.is_some());
        assert!((step - 1..=step + 1).contains(&matched.unwrap()));
    }

    #[test]
    fn matched_timestep_rejects_garbage() {
        let secret = test_secret();
        assert!(totp_matched_timestep(&secret, "alice", "abcde").is_none());
        assert!(totp_matched_timestep(&secret, "alice", "12345").is_none());
        assert!(totp_matched_timestep(&secret, "alice", "12345678").is_none());
        assert!(totp_matched_timestep(&secret, "alice", "000000x").is_none());
    }

    #[test]
    fn matched_timestep_accepts_previous_step_with_skew() {
        let secret = test_secret();
        let totp = build_totp(&secret, "alice").unwrap();
        let prev_step = chrono::Utc::now().timestamp().div_euclid(30) - 1;
        let code = totp.generate((prev_step * 30) as u64).to_string();
        assert_eq!(
            totp_matched_timestep(&secret, "alice", &code),
            Some(prev_step)
        );
    }
}
