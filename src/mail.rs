use crate::cfg::CONFIG;
use anyhow::Result;
use rumbo_http_client::{HttpClient, HttpMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct ForgotPasswordMail {
    pub recipient: String,
    pub addresser: String,
    pub attribs: Attribs,
}

#[derive(Serialize, Deserialize)]
pub struct Attribs {
    pub reset_link: String,
}

pub struct Mail {}

impl Mail {
    pub async fn send_email(mail: ForgotPasswordMail) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(
            "X-API-Key".to_string(),
            CONFIG.mail_server_api_key.to_string(),
        );
        match HttpClient::fetch::<ForgotPasswordMail>(
            HttpMethod::POST,
            format!("{}/api/batch_mail/api/send", CONFIG.mail_server_url),
            Some(headers),
            Some(mail),
        )
        .await
        {
            Ok(_) => {
                println!("succeed send email");
            }
            Err(e) => {
                println!("failed send email caused {:?}", e)
            }
        };
        Ok(())
    }
}
