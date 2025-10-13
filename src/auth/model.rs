use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct User {
    pub user_id: Option<i32>,
    pub username: String,
    pub password: Option<String>,
    pub email: Option<String>,
    pub provider: String,
    pub provider_id: Option<String>,
    pub role_id: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginRegister {
    pub username: String,
    pub password: String,
    pub role_id: i32,
}

#[derive(Serialize, Deserialize)]
pub struct ForgotPassword {
    pub username: String,
}

#[derive(Serialize, Deserialize)]
pub struct ResetPassword {
    pub password: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct SigninGoogle {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterGoogle {
    pub token: String,
    pub role_id: i32,
}
