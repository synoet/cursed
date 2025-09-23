use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{FromRef, FromRequestParts, Path, Query, ws::Message},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use cursed_core::{
    crypto::{Ed25519Pk, Ed25519Sig},
    protocol::TomeId,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rooms::Room;
use serde::Deserialize;

use crate::AppState;

#[derive(Clone)]
pub struct TomeRoom(pub Arc<Room<Ed25519Pk, Message, Message>>);

impl<S> FromRequestParts<S> for TomeRoom
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let Path(room_id): Path<TomeId> =
            Path::from_request_parts(parts, state).await.map_err(|_| {
                (axum::http::StatusCode::BAD_REQUEST, "Invalid room ID").into_response()
            })?;

        match app_state.rooms.get(&room_id) {
            Some(room) => Ok(room.clone()),
            None => Err((axum::http::StatusCode::NOT_FOUND, "Room not found").into_response()),
        }
    }
}

#[derive(Deserialize)]
pub struct AuthorizationParams {
    timestamp: u64,
    signature: String,
    public_key: String,
}

#[derive(Clone)]
pub struct AuthPrimaryKey(pub Ed25519Pk);

impl<S> FromRequestParts<S> for AuthPrimaryKey
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(room_id): Path<TomeId> =
            Path::from_request_parts(parts, state).await.map_err(|_| {
                tracing::error!("Invalid room ID");
                (axum::http::StatusCode::BAD_REQUEST, "Invalid room ID").into_response()
            })?;

        let Query(AuthorizationParams {
            timestamp,
            signature,
            public_key,
        }) = Query::<AuthorizationParams>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                tracing::error!("Invalid authorization params");
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "Invalid authorization params",
                )
                    .into_response()
            })?;

        let public_key = Ed25519Pk::from_base64(&public_key).map_err(|_| {
            tracing::error!("Invalid public key");
            (axum::http::StatusCode::BAD_REQUEST, "Invalid public key").into_response()
        })?;

        let verifyng_key = VerifyingKey::from_bytes(&public_key.0).map_err(|_| {
            tracing::error!("Invalid public key");
            (axum::http::StatusCode::BAD_REQUEST, "Invalid public key").into_response()
        })?;

        let signature = Ed25519Sig::from_base64(&signature).map_err(|_| {
            tracing::error!("Invalid signature");
            (axum::http::StatusCode::BAD_REQUEST, "Invalid signature").into_response()
        })?;

        let signature = Signature::from_bytes(&signature.0);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        if now.abs_diff(timestamp) > 30 {
            return Err((StatusCode::UNAUTHORIZED, "Expired timestamp").into_response());
        }

        let message = format!("cursed:{}:{}", room_id.0, timestamp);

        match verifyng_key.verify_strict(message.as_bytes(), &signature) {
            Ok(()) => Ok(AuthPrimaryKey(public_key)),
            Err(_) => Err((StatusCode::UNAUTHORIZED, "Invalid signature").into_response()),
        }
    }
}
