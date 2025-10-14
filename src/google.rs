use crate::utils::des_from_str;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rumbo_http_client::{HttpClient, HttpMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleIdTokenPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: String,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub hd: Option<String>, // hosted domain for Google Workspace
}

#[derive(Debug, Deserialize, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Clone)]
struct CachedCerts {
    certs: HashMap<String, String>,
    expires_at: SystemTime,
}

pub struct GoogleTokenVerifier {
    client_id: String,
    cert_cache: Arc<RwLock<Option<CachedCerts>>>,
}

impl GoogleTokenVerifier {
    pub fn new(client_id: String) -> Self {
        GoogleTokenVerifier {
            client_id,
            cert_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch and cache Google's public keys
    async fn fetch_public_keys(
        &self,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        // Check if cache is still valid
        {
            let cache = self.cert_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if SystemTime::now() < cached.expires_at {
                    return Ok(cached.certs.clone());
                }
            }
        }
        let response = match HttpClient::fetch(
            HttpMethod::GET,
            "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            None,
            None::<()>,
        )
        .await
        {
            Ok(response) => response,
            Err(e) => {
                return Err(Box::new(e));
            }
        };

        let cache_control = match response.headers.get("cache-control") {
            Some(cc) => cc,
            None => "max-age=3600",
        };

        let ttl_seconds = extract_ttl(cache_control);
        let expires_at = SystemTime::now() + Duration::from_secs(ttl_seconds as u64);

        let jwk_set: JwkSet = match &response.body {
            Some(body) => {
                let body = remove_chunked_encoding(body);
                println!("{:?}", body);

                match des_from_str(&body) {
                    Ok(body) => body,
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            None => return Err(Box::new(Error)),
        };
        let mut certs = HashMap::new();

        for jwk in jwk_set.keys {
            certs.insert(jwk.kid, format!("{},{}", jwk.n, jwk.e));
        }

        // Update cache
        {
            let mut cache = self.cert_cache.write().await;
            *cache = Some(CachedCerts {
                certs: certs.clone(),
                expires_at,
            });
        }

        Ok(certs)
    }

    /// Verify the Google ID token
    pub async fn verify(
        &self,
        token: &str,
    ) -> Result<GoogleIdTokenPayload, Box<dyn std::error::Error>> {
        // Decode header to get kid
        let header = decode_header(token)?;
        let kid = header.kid.ok_or("Missing 'kid' in token header")?;

        // Get public keys
        let certs = self.fetch_public_keys().await?;
        let cert_data = certs.get(&kid).ok_or("Certificate kid not found")?;

        // Create decoding key from cert
        let (n, e) = cert_data.split_once(',').ok_or("Invalid cert format")?;

        let decoding_key = DecodingKey::from_rsa_components(n, e)?;

        // Verify token
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        let data = decode::<GoogleIdTokenPayload>(token, &decoding_key, &validation)?;

        // Verify exp claim (already done by validation, but explicit check)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

        if data.claims.exp < now {
            return Err("Token expired".into());
        }

        Ok(data.claims)
    }
}

/// Extract TTL from Cache-Control header
fn extract_ttl(cache_control: &str) -> usize {
    cache_control
        .split(',')
        .find_map(|part| {
            let part = part.trim();
            if part.starts_with("max-age=") {
                part.strip_prefix("max-age=")
                    .and_then(|s| s.parse::<usize>().ok())
            } else {
                None
            }
        })
        .unwrap_or(3600)
}

//"409\r\n{\n  \"keys\": [\n    {\n      \"alg\": \"RS256\",\n      \"kty\": \"RSA\",\n      \"e\": \"AQAB\",\n      \"n\": \"vG5pJE-wQNbH7tvZU3IgjdeHugdw2x5eXPe47vOP3dIy4d9HnCWSTroJLtPYA1SFkcl8FlgrgWspCGBzJ8gwMo81Tk-5hX2pWXsNKrOH8R01jFqIn_UBwhmqU-YDde1R4w9upLzwNyl9Je_VY65EKrMOZG9u4UYtzTkNFLf1taBe0gIM20VSAcClUhTGpE3MX9lXxQqN3Hoybja7C_SZ8ymcnB5h-20ynZGgQybZRU43KcZkIMK2YKkLd7Tn4UQeSRPbmlbm5a0zbs5GpcYB7MONYh7MD16FTS72-tYKX-kDh3NltO6HQsV9pfoOi7qJrFaYWP3AHd_h7mWTHIkNjQ\",\n      \"use\": \"sig\",\n      \"kid\": \"c8ab71530972bba20b49f78a09c9852c43ff9118\"\n    },\n    {\n      \"e\": \"AQAB\",\n      \"kid\": \"fb9f9371d5755f3e383a40ab3a172cd8baca517f\",\n      \"use\": \"sig\",\n      \"kty\": \"RSA\",\n      \"n\": \"to2hcsFNHKquhCdUzXWdP8yxnGqxFWJlRT7sntBgp47HwxB9HFc-U_AB1JT8xe1hwDpWTheckoOfpLgo7_ROEsKpVJ_OXnotL_dgNwbprr-T_EFJV7qOEdHL0KmrnN-kFNLUUSqSChPYVh1aEjlPfXg92Yieaaz2AMMtiageZrKoYnrGC0z4yPNYFj21hO1x6mvGIjmpo6_fe91o-buZNzzkmYlGsFxdvUxYAvgk-5-7D10UTTLGh8bUv_BQT3aRFiVRS5d07dyCJ4wowzxYlPSM6lnfUlvHTWyPL4JysMGeu-tbPA-5QvwCdSGpfWFQbgMq9NznBtWb99r1UStpBQ\",\n      \"alg\": \"RS256\"\n    }\n  ]\n}\n\r\n0"
/// Remove chunked transfer encoding artifacts
/// Removes hex chunk sizes (like "409\r\n") and final "0\r\n"
fn remove_chunked_encoding(body: &str) -> String {
    // Split by \r\n to get chunks
    let lines: Vec<&str> = body.split("\r\n").collect();
    let mut result = String::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Skip empty lines
        if line.is_empty() {
            i += 1;
            continue;
        }

        // Check if this line is a hex chunk size (like "409" or "0")
        if line.chars().all(|c| c.is_ascii_hexdigit()) {
            let chunk_size = usize::from_str_radix(line, 16).unwrap_or(0);

            // If chunk size is 0, we're at the end
            if chunk_size == 0 {
                break;
            }

            // Skip the size line, next line is the actual data
            i += 1;
        } else {
            // This is actual JSON data, add it
            result.push_str(line);
            i += 1;
        }
    }

    result
}
