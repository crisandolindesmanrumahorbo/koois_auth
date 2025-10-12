use chrono::Utc;
use request_http_parser::parser::Request;

use super::{
    model::{CreatePermission, Permission},
    repo::PermissionRepository,
};
use crate::{
    constants::{BAD_REQUEST, INTERNAL_ERROR, NO_CONTENT, OK_RESPONSE},
    db::DBConn,
    error::CustomError,
    utils::{Claims, des_from_str, ser_to_str},
};

pub struct PermissionSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    repository: PermissionRepository<DB>,
}

impl<DB> PermissionSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        PermissionSvc {
            repository: PermissionRepository::new(pool),
        }
    }

    pub async fn get_permissions(&self) -> (String, String) {
        // only manages users can get all permission
        let permissions = match self.repository.fetch_permissions().await {
            Ok(user) => user,
            Err(why) => match why {
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

    pub async fn create_permission(
        &self,
        _claims: Option<Claims>,
        request: &Request,
    ) -> (String, String) {
        // check authorzitaion by cek their role_id
        // next this should check to redis
        // let claims = match claims {
        //     Some(claims) => claims,
        //     None => {
        //         println!("serde error");
        //         return (INTERNAL_ERROR.to_string(), "".to_string());
        //     }
        // };
        let req_permission: CreatePermission = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };

        let new_permission = Permission {
            name: req_permission.name,
            permission_id: None,
            description: req_permission.description,
            created_at: Utc::now(),
        };
        match self.repository.insert_permission(&new_permission).await {
            Ok(_) => (NO_CONTENT.to_string(), "".to_string()),
            Err(err) => match err {
                CustomError::PermissionExists => {
                    eprintln!("Error insert: {:#?}", err);
                    (BAD_REQUEST.to_string(), "Already registered".to_string())
                }
                error => {
                    eprintln!("Error insert permission db: {:#?}", error);
                    (INTERNAL_ERROR.to_string(), "".to_string())
                }
            },
        }
    }
}
