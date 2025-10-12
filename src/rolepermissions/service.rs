use super::repo::RolePermissionRepository;
use crate::{
    constants::{BAD_REQUEST, INTERNAL_ERROR, NO_CONTENT, NOT_FOUND, OK_RESPONSE},
    db::DBConn,
    error::CustomError,
    utils::{Claims, ser_to_str},
};

pub struct RolePermissionSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    repository: RolePermissionRepository<DB>,
}

impl<DB> RolePermissionSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        RolePermissionSvc {
            repository: RolePermissionRepository::new(pool),
        }
    }

    pub async fn get_role_permissions_by_role_id(
        &self,
        claims: Option<Claims>,
    ) -> (String, String) {
        let claims = match claims {
            Some(claims) => claims,
            None => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };

        let permissions = match self.repository.fetch_role_permissions(claims.role_id).await {
            Ok(user) => user,
            Err(why) => match why {
                CustomError::RoleNotFound => {
                    return (NOT_FOUND.to_string(), "".to_string());
                }
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };
        let response_json = match ser_to_str(&permissions) {
            Ok(json) => json,
            Err(_) => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        (OK_RESPONSE.to_string(), response_json)
    }

    pub async fn insert_role_permissions(
        &self,
        role_id: i32,
        permission_ids: Vec<i32>,
    ) -> (String, String) {
        match self
            .repository
            .insert_role_permissions(role_id, permission_ids)
            .await
        {
            Ok(_) => (NO_CONTENT.to_string(), "".to_string()),
            Err(err) => match err {
                CustomError::RolePermissionExists => {
                    eprintln!("Error insert: {:#?}", err);
                    (BAD_REQUEST.to_string(), "Already registered".to_string())
                }
                error => {
                    eprintln!("Error insert role permission db: {:#?}", error);
                    (INTERNAL_ERROR.to_string(), "".to_string())
                }
            },
        }
    }
}
