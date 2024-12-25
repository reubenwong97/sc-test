#![allow(unused)]

use axum::{
    body::Bytes,
    extract::{Json, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use chrono::prelude::*;
use derive_more::From;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::env;
use std::error::Error;
use std::{collections::HashMap, str};
use subtle::ConstantTimeEq;
use tracing::info;

// Constants for Twitch message headers (lowercase for case-insensitive comparison)
const TWITCH_MESSAGE_ID: &str = "twitch-eventsub-message-id";
const TWITCH_MESSAGE_TIMESTAMP: &str = "twitch-eventsub-message-timestamp";
const TWITCH_MESSAGE_SIGNATURE: &str = "twitch-eventsub-message-signature";
const MESSAGE_TYPE: &str = "twitch-eventsub-message-type";

// Notification message types
const MESSAGE_TYPE_VERIFICATION: &str = "webhook_callback_verification";
const MESSAGE_TYPE_NOTIFICATION: &str = "notification";
const MESSAGE_TYPE_REVOCATION: &str = "revocation";

// HMAC prefix for Twitch signatures
const HMAC_PREFIX: &str = "sha256=";

#[derive(Debug, Deserialize)]
struct TwitchTransport {
    method: String,
    callback: String,
}

#[derive(Debug, Deserialize)]
struct TwitchCondition {
    broadcaster_user_id: String,
}

#[derive(Debug, Deserialize)]
struct TwitchEvent {
    user_id: String,
    user_login: String,
    user_name: String,
    broadcaster_user_id: String,
    broadcaster_user_login: String,
    broadcaster_user_name: String,
    followed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct TwitchSubscription {
    id: String,
    status: String,
    #[serde(rename = "type")]
    subscription_type: String,
    version: String,
    condition: TwitchCondition,
    cost: u64,
    transport: TwitchTransport,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct TwitchPayload {
    subscription: TwitchSubscription,
    event: Option<TwitchEvent>,
    challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthParams {
    code: Option<String>,
    scope: Option<String>,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
}

async fn handle_auth(
    Query(params): Query<AuthParams>,
) -> Result<axum::response::Response, StatusCode> {
    if params.error.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    };
    let code = params.code.unwrap();
    let scope = params.scope.unwrap();
    let state = params.state;

    let auth_url = "https://id.twitch.tv/oauth2/token";
    let client = reqwest::Client::new();
    let params = [
        ("client_id", env::var("CLIENT_ID").unwrap()),
        ("client_secret", env::var("CLIENT_SECRET").unwrap()),
        ("code", code),
        ("grant_type", "authorization_code".to_string()),
        (
            "redirect_uri",
            "http://localhost:8080/handle_auth/".to_string(),
        ),
    ];
    let res = client.post(auth_url).form(&params).send().await;

    // TODO: Change this, currently silence warnings
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn handle_twitch_payload(
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, StatusCode> {
    info!("Headers:\n{:#?}", headers);
    info!("Bytes:\n{:#?}", body);
    let payload: Json<TwitchPayload> = Json::from_bytes(&body).unwrap();
    info!("Payload:\n{:#?}", payload);

    let secret = get_secret();
    let message = get_hmac_message(&headers, &body)?;
    let computed_hmac = get_hmac(&secret, &message);
    let full_computed_hmac = format!("{HMAC_PREFIX}{computed_hmac}");

    let signature = headers
        .get(TWITCH_MESSAGE_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;

    if !verify_message(&full_computed_hmac, signature) {
        return Err(StatusCode::BAD_REQUEST);
    };

    let message_type = headers
        .get(MESSAGE_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    match message_type {
        MESSAGE_TYPE_VERIFICATION => {
            let challenge = payload.challenge.clone().ok_or(StatusCode::BAD_REQUEST)?;

            info!("Challenge: {}", challenge);
            Ok(challenge.into_response())
        }
        MESSAGE_TYPE_REVOCATION => {
            info!(
                "{} notifications revoked!",
                payload.subscription.subscription_type
            );

            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => {
            info!("Not handling now");
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

// Get the secret (replace with secure storage in production)
fn get_secret() -> String {
    // TODO: Implement secure secret retrieval
    "5f1a6e7cd2e7137ccf9e15b2f43fe63949eb84b1db83c1d5a867dc93429de4e4".to_string()
}

// Construct the HMAC message from headers and body
fn get_hmac_message(headers: &HeaderMap, body: &Bytes) -> Result<String, StatusCode> {
    let message_id = headers
        .get(TWITCH_MESSAGE_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let message_timestamp = headers
        .get(TWITCH_MESSAGE_TIMESTAMP)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let body_str = str::from_utf8(body).map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(format!("{message_id}{message_timestamp}{body_str}"))
}

// Compute HMAC
fn get_hmac(secret: &str, message: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    // Convert to hex
    format!("{:x}", mac.finalize().into_bytes())
}

// Verify message signature
fn verify_message(computed_hmac: &str, signature: &str) -> bool {
    // Constant-time comparison to prevent timing attacks
    computed_hmac.as_bytes().ct_eq(signature.as_bytes()).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv()?;
    tracing_subscriber::fmt().with_target(false).init();
    // Create router
    let app = Router::new()
        .route("/eventsub/", post(handle_twitch_payload))
        .route("/handle_auth/", post(handle_auth));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    info!("Server listening on http://localhost:8080");

    // Start server
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
