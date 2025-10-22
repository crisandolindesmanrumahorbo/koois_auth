use crate::{
    cfg::CONFIG,
    constants::{BAD_REQUEST, UNAUTHORIZED},
    utils::{Claims, extract_token, verify_jwt},
};
use anyhow::{Context, Result, anyhow};
use request_http_parser::parser::{Method, Request};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct Middleware {}

impl Middleware {
    pub async fn new(stream: &mut TcpStream) -> Result<(Request, Option<Claims>)> {
        let mut buffer = vec![0; CONFIG.request_max_byte];
        let size = stream
            .read(&mut buffer)
            .await
            .context("Failed to read stream")?;
        if size >= CONFIG.request_max_byte {
            let _ = stream
                .write_all(format!("{}{}", BAD_REQUEST, "Requets too large").as_bytes())
                .await
                .context("Failed to write");

            let _ = stream.flush().await.context("Failed to flush");

            return Err(anyhow!("request too large"));
        }
        let req_str = String::from_utf8_lossy(&buffer[..size]);
        println!("{}", req_str);
        let request = match Request::new(&req_str) {
            Ok(req) => req,
            Err(e) => {
                println!("{}", e);
                let _ = stream
                    .write_all(format!("{}{}", BAD_REQUEST, e).as_bytes())
                    .await
                    .context("Failed to write");

                let _ = stream.flush().await.context("Failed to flush");
                return Err(anyhow!("request format invalid"));
            }
        };
        if !request.path.contains("protected") || request.method == Method::OPTIONS {
            return Ok((request, None));
        }

        let token_opt = match extract_token(&request.headers) {
            Some(token) => Some(token),
            _ => None,
        };
        let token = match token_opt {
            Some(token) => token,
            None => {
                stream
                    .write_all(
                        format!(
                            "{}{}",
                            UNAUTHORIZED.to_string(),
                            "401 unathorized".to_string()
                        )
                        .as_bytes(),
                    )
                    .await?;
                return Err(anyhow!("extract token error"));
            }
        };

        let claims = match verify_jwt(&token) {
            Ok(user_id) => user_id,
            Err(_) => {
                stream
                    .write_all(
                        format!(
                            "{}{}",
                            UNAUTHORIZED.to_string(),
                            "401 unathorized".to_string()
                        )
                        .as_bytes(),
                    )
                    .await?;
                return Err(anyhow!("token unathorized"));
            }
        };
        Ok((request, Some(claims)))
    }
}
