use super::model::GetRolePermissions;
use crate::{db::DBConn, error::CustomError};

pub struct RolePermissionRepository<DB: DBConn> {
    db: DB,
}

impl<DB: DBConn> RolePermissionRepository<DB> {
    pub fn new(db: DB) -> Self {
        RolePermissionRepository { db }
    }

    pub async fn fetch_permissions(
        &self,
        role_id: i32,
    ) -> Result<Vec<GetRolePermissions>, CustomError> {
        self.db
            .fetch_permissions(role_id)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => CustomError::RoleNotFound,
                _ => CustomError::DBError(e),
            })
    }
}
