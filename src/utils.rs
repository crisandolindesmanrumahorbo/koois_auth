use crate::auth;
use crate::cfg::CONFIG;
use crate::error::CustomError;
use anyhow::{Context, Result};
use auth::model::User;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum ClaimType {
    Login,
    ForgotPassword,
}

impl TryFrom<&str> for ClaimType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, anyhow::Error> {
        match value {
            "ForgotPassword" => Ok(ClaimType::ForgotPassword),
            "Login" => Ok(ClaimType::Login),
            _ => Err(anyhow::anyhow!("Claim type not found")),
        }
    }
}

impl ToString for ClaimType {
    fn to_string(&self) -> String {
        match self {
            ClaimType::ForgotPassword => "ForgotPassword".to_string(),
            ClaimType::Login => "Login".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub username: String,
    pub role_id: i32,
    pub claim_type: ClaimType,
}

pub fn des_from_str<T: for<'a> Deserialize<'a> + Serialize>(
    string: &str,
) -> Result<T, serde_json::Error> {
    serde_json::from_str(string)
}

pub fn ser_to_str<T: for<'a> Deserialize<'a> + Serialize>(
    t: &T,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(t)
}

pub fn encrypt(value: &str) -> String {
    hash(value, DEFAULT_COST).expect("generate password failed")
}

pub fn is_password_valid(value: &str, value1: &str) -> bool {
    verify(value, value1).unwrap_or(false)
}

fn get_private_key() -> Result<EncodingKey, CustomError> {
    let enc_key =
        EncodingKey::from_rsa_pem(&CONFIG.jwt_private_key.replace("\\n", "\n").as_bytes())
            .map_err(CustomError::EncodeError)?;
    Ok(enc_key)
}

pub fn create_jwt(user: User, claim_type: ClaimType) -> Result<String> {
    let private_key = get_private_key().context("Failed Get Private Key")?;
    let expiration = match claim_type {
        ClaimType::Login => Utc::now()
            .checked_add_signed(Duration::hours(1)) // Token valid for 1 hours
            .expect("Invalid timestamp")
            .timestamp() as usize,
        ClaimType::ForgotPassword => Utc::now()
            .checked_add_signed(Duration::minutes(15)) // Token valid for 15
            // minutes
            .expect("Invalid timestamp")
            .timestamp() as usize,
    };
    let claims = Claims {
        sub: user.user_id.unwrap().to_string(),
        exp: expiration,
        username: user.username.to_string(),
        role_id: user.role_id,
        claim_type,
    };

    encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &private_key,
    )
    .context("Failed to Encode the JWT")
}

pub fn extract_token(
    headers: &std::collections::HashMap<std::string::String, std::string::String>,
) -> Option<String> {
    headers.get("authorization").and_then(|s| {
        let mut parts = s.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("Bearer"), Some(token)) => Some(token.to_string()),
            _ => None,
        }
    })
}

pub fn verify_jwt(token: &str) -> Result<Claims, &'static str> {
    let public_key = jsonwebtoken::DecodingKey::from_rsa_pem(
        &CONFIG.jwt_public_key.replace("\\n", "\n").as_bytes(),
    )
    .expect("Invalid public key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<crate::utils::Claims>(token, &public_key, &validation)
        .map_err(|e| {
            println!("JWT error: {:?}", e);
            "Invalid token"
        })?;

    Ok(token_data.claims)
}
