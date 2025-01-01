use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use reqwest::header::CACHE_CONTROL;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseTokenClaims {
    pub exp: u64,
    pub iat: u64,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub auth_time: u64,
}

struct CachedKeys {
    keys: HashMap<String, String>,
    expiration: SystemTime,
}

pub struct FirebaseTokenVerifier {
    project_id: String,
    cached_keys: Arc<Mutex<Option<CachedKeys>>>,
}

const GOOGLE_CERTS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

impl FirebaseTokenVerifier {
    pub fn new(project_id: String) -> Self {
        Self {
            project_id,
            cached_keys: Arc::new(Mutex::new(None)),
        }
    }

    async fn fetch_public_keys(&self) -> Result<HashMap<String, String>> {
        if let Some(cached) = self.cached_keys.lock().unwrap().as_ref() {
            if SystemTime::now() < cached.expiration {
                return Ok(cached.keys.clone());
            }
        }

        let client = reqwest::Client::new();
        let response = client.get(GOOGLE_CERTS_URL).send().await?;
        let cache_duration = if let Some(cache_control) = response.headers().get(CACHE_CONTROL) {
            if let Ok(cache_str) = cache_control.to_str() {
                parse_max_age(cache_str).unwrap_or(3600)
            } else {
                3600
            }
        } else {
            3600
        };

        let keys: HashMap<String, String> = response.json().await?;
        let expiration = SystemTime::now() + Duration::from_secs(cache_duration);
        *self.cached_keys.lock().unwrap() = Some(CachedKeys {
            keys: keys.clone(),
            expiration,
        });

        Ok(keys)
    }

    pub async fn verify_token(&self, token: &str) -> Result<FirebaseTokenClaims> {
        let header = decode_header(token)?;

        if header.alg != Algorithm::RS256 {
            return Err(anyhow!("Invalid algorithm. Expected RS256"));
        }

        let kid = header.kid.ok_or_else(|| anyhow!("No 'kid' claim in token header"))?;

        let public_keys = self.fetch_public_keys().await?;
        let public_key = public_keys
            .get(&kid)
            .ok_or_else(|| anyhow!("No matching public key found for kid: {}", kid))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.project_id]);
        validation.set_issuer(&[format!(
            "https://securetoken.google.com/{}",
            self.project_id
        )]);

        let key = DecodingKey::from_rsa_pem(public_key.as_bytes())?;
        let token_data = decode::<FirebaseTokenClaims>(token, &key, &validation)?;
        let claims = token_data.claims;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        if claims.exp <= current_time {
            return Err(anyhow!("Token has expired"));
        }

        if claims.iat > current_time {
            return Err(anyhow!("Token issued in the future"));
        }

        if claims.auth_time > current_time {
            return Err(anyhow!("Auth time is in the future"));
        }

        if claims.sub.is_empty() {
            return Err(anyhow!("Subject claim is empty"));
        }

        Ok(claims)
    }
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .find(|dir| dir.trim().starts_with("max-age="))
        .and_then(|max_age_dir| {
            max_age_dir
                .trim()
                .strip_prefix("max-age=")
                .and_then(|age| age.parse().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_max_age() {
        assert_eq!(parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(parse_max_age("max-age=3600, public"), Some(3600));
        assert_eq!(parse_max_age("public, max-age=3600"), Some(3600));
        assert_eq!(parse_max_age("no-cache"), None);
    }
}