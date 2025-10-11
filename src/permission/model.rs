use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct Permission {
    pub permission_id: Option<i32>,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}
