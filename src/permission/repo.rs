use super::model::Permission;
use crate::{db::DBConn, error::CustomError};

pub struct PermissionRepository<DB: DBConn> {
    db: DB,
}

impl<DB: DBConn> PermissionRepository<DB> {
    pub fn new(db: DB) -> Self {
        PermissionRepository { db }
    }

    pub async fn fetch_permissions(&self) -> Result<Vec<Permission>, CustomError> {
        self.db.fetch_permissions().await.map_err(|e| match e {
            _ => CustomError::DBError(e),
        })
    }

    pub async fn insert_permission(&self, new_permission: &Permission) -> Result<i32, CustomError> {
        let permission_id = match self.db.insert_permission(new_permission).await {
            Ok(permission_id) => permission_id,
            Err(e) => match e {
                sqlx::Error::Database(err) if err.is_unique_violation() => {
                    return Err(CustomError::PermissionExists);
                }
                _ => return Err(CustomError::DBError(e)),
            },
        };
        Ok(permission_id)
    }
}
