use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct GetUsers {
    pub user_id: Option<i32>,
    pub username: String,
    pub email: Option<String>,
    pub provider: String,
    pub role_id: i32,
    pub created_at: DateTime<Utc>,
}
