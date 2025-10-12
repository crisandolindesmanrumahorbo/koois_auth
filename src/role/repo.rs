use super::model::Role;
use crate::{db::DBConn, error::CustomError};

pub struct RoleRepository<DB: DBConn> {
    db: DB,
}

impl<DB: DBConn> RoleRepository<DB> {
    pub fn new(db: DB) -> Self {
        RoleRepository { db }
    }

    pub async fn fetch_roles(&self) -> Result<Vec<Role>, CustomError> {
        self.db.fetch_roles().await.map_err(|e| match e {
            _ => CustomError::DBError(e),
        })
    }

    pub async fn insert_role(&self, new_role: &Role) -> Result<i32, CustomError> {
        let role_id = match self.db.insert_role(new_role).await {
            Ok(role_id) => role_id,
            Err(e) => match e {
                sqlx::Error::Database(err) if err.is_unique_violation() => {
                    return Err(CustomError::RoleExists);
                }
                _ => return Err(CustomError::DBError(e)),
            },
        };
        Ok(role_id)
    }
}
