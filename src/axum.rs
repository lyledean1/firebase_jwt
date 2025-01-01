use async_trait::async_trait;
use axum::{
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::{Next},
    response::Response,
    body::Body,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use tokio;
use crate::FirebaseTokenVerifier;

#[derive(Debug)]
struct AppError(anyhow::Error);

#[derive(Clone)]
pub struct AppState {
    pub jwt_decoding_key: DecodingKey,
    pub google_project_id: String,
}

#[derive(Debug, Deserialize)]
struct GoogleCredentials {
    private_key: String,
    client_email: String,
}

impl AppState {
    pub fn from_google_credentials(google_project_id: String, creds_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let creds_file = fs::read_to_string(creds_path)?;
        let creds: Value = serde_json::from_str(&creds_file)?;
        let private_key = creds["private_key"]
            .as_str()
            .ok_or("private_key not found")?;
        let jwt_decoding_key = DecodingKey::from_rsa_pem(private_key.as_bytes())?;
        Ok(Self { google_project_id, jwt_decoding_key })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn axum_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>
{

    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        tracing::debug!("No bearer token provided for request");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header["Bearer ".len()..];
    let verifier = FirebaseTokenVerifier::new(state.google_project_id.clone());
    let claims = verifier.verify_token(token).await;
    request.extensions_mut().insert(claims.unwrap());
    Ok(next.run(request).await)
}

#[derive(Debug)]
struct AuthClaims(Claims);

#[async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(AuthClaims(claims.clone()))
    }
}
