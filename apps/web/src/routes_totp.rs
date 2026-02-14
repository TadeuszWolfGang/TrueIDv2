//! TOTP 2FA setup, verification, and backup-code endpoints.

use axum::{http::StatusCode, response::IntoResponse, Json};
use rand::Rng;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
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

    let generated = Secret::generate_secret();
    let secret_encoded = generated.to_encoded().to_string();
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
    let ok = verify_totp_code_for_user_secret(&secret, &username, &body.code);
    if !ok {
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
/// Parameters: `db` - database handle, `user` - user record, `code` - submitted code.
/// Returns: `true` when code is valid.
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
            if verify_totp_code_for_user_secret(&secret, &user.username, code) {
                return true;
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
    let secret = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("invalid secret: {e}"))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("TrueID".to_string()),
        username.to_string(),
    )
    .map_err(|e| anyhow::anyhow!("totp init failed: {e}"))
}

/// Verifies one TOTP code for given secret.
///
/// Parameters: `secret_base32` - encoded secret, `username` - account label, `code` - user code.
/// Returns: true when code is valid.
pub(crate) fn verify_totp_code_for_user_secret(
    secret_base32: &str,
    username: &str,
    code: &str,
) -> bool {
    let clean = code.trim().replace(' ', "");
    if clean.len() < 6 {
        return false;
    }
    let totp = match build_totp(secret_base32, username) {
        Ok(v) => v,
        Err(_) => return false,
    };
    totp.check_current(&clean).unwrap_or(false)
}

/// Generates 10 random one-time backup codes.
///
/// Returns: vector of codes in `XXXX-XXXX` format.
fn generate_backup_codes() -> Vec<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(10);
    for _ in 0..10 {
        let left: String = (0..4)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
            .collect();
        let right: String = (0..4)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
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
    db.set_user_totp_backup_codes_enc(user_id, Some(&new_enc))
        .await
        .is_ok()
}
