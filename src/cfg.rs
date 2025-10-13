use once_cell::sync::Lazy;

#[derive(serde::Deserialize)]
pub struct AppConfig {
    pub jwt_public_key: String,
    pub database_url: String,
    pub jwt_private_key: String,
    pub google_client_id: String,
    pub request_max_byte: usize,
    pub mail_server_url: String,
    pub mail_server_api_key: String,
}

// Initialize config once
pub static CONFIG: Lazy<AppConfig> = Lazy::new(|| {
    dotenvy::dotenv().ok();

    config::Config::builder()
        .add_source(config::Environment::default())
        .set_default("request_max_byte", 2048)
        .expect("set valid env")
        .build()
        .expect("")
        .try_deserialize()
        .expect("env not ready")
});
