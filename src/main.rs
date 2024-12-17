use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::str;
use subtle::ConstantTimeEq;

use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info};

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

// Deserialize structs for JSON parsing
#[derive(Debug, Deserialize)]
struct TwitchNotification {
    subscription: Subscription,
    event: serde_json::Value,
    challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Subscription {
    #[serde(rename = "type")]
    subscription_type: String,
    status: Option<String>,
    condition: Option<serde_json::Value>,
}

// Main handler for Twitch EventSub webhook
async fn handle_eventsub(
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, StatusCode> {
    // Get secret (in a real-world scenario, this would come from secure storage)
    let secret = get_secret();

    // Construct the HMAC message
    let message = get_hmac_message(&headers, &body)?;

    // Compute HMAC
    let computed_hmac = get_hmac(&secret, &message);
    let full_computed_hmac = format!("{}{}", HMAC_PREFIX, computed_hmac);

    // Get the signature from headers
    let signature = headers
        .get(TWITCH_MESSAGE_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;

    // Verify signature
    if !verify_message(&full_computed_hmac, signature) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Parse the notification
    let notification: TwitchNotification = match serde_json::from_slice(&body) {
        Ok(n) => n,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Get message type from headers
    let message_type = headers
        .get(MESSAGE_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    info!("Message type: {message_type}");

    // Process different message types
    match message_type {
        MESSAGE_TYPE_NOTIFICATION => {
            // Log event details
            info!(
                "Event type: {}",
                notification.subscription.subscription_type
            );
            info!(
                "Event data: {}",
                serde_json::to_string_pretty(&notification.event)
                    .unwrap_or_else(|_| "Failed to parse event".to_string())
            );

            Ok(StatusCode::NO_CONTENT.into_response())
        }
        MESSAGE_TYPE_VERIFICATION => {
            // Return the challenge for webhook verification
            let challenge = notification.challenge.ok_or(StatusCode::BAD_REQUEST)?;

            info!("Challenge: {}", challenge);
            Ok(axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(challenge.into())
                .unwrap())
        }
        MESSAGE_TYPE_REVOCATION => {
            // Log revocation details
            info!(
                "{} notifications revoked!",
                notification.subscription.subscription_type
            );

            if let (Some(status), Some(condition)) = (
                &notification.subscription.status,
                &notification.subscription.condition,
            ) {
                info!("Reason: {}", status);
                info!(
                    "Condition: {}",
                    serde_json::to_string_pretty(condition)
                        .unwrap_or_else(|_| "Failed to parse condition".to_string())
                );
            }

            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => {
            info!("Unknown message type: {}", message_type);
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

    Ok(format!("{}{}{}", message_id, message_timestamp, body_str))
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
async fn main() {
    tracing_subscriber::fmt().with_target(false).json().init();
    // Create router
    let app = Router::new()
        .route("/eventsub/", post(handle_eventsub))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    info!("Server listening on http://localhost:8080");

    // Start server
    axum::serve(listener, app).await.unwrap();
}
