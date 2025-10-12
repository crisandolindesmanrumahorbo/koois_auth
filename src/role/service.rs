use std::sync::Arc;

use chrono::Utc;
use request_http_parser::parser::Request;

use super::{
    model::{CreateRole, Role},
    repo::RoleRepository,
};
use crate::{
    constants::{BAD_REQUEST, INTERNAL_ERROR, OK_RESPONSE},
    db::DBConn,
    error::CustomError,
    rolepermissions::service::RolePermissionSvc,
    utils::{Claims, des_from_str, ser_to_str},
};

pub struct RoleSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    repository: RoleRepository<DB>,
}

impl<DB> RoleSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        RoleSvc {
            repository: RoleRepository::new(pool),
        }
    }

    pub async fn get_roles(&self, _claims: Option<Claims>) -> (String, String) {
        // only manages users can get all permission
        let roles = match self.repository.fetch_roles().await {
            Ok(user) => user,
            Err(why) => match why {
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };
        let response_json = match ser_to_str(&roles) {
            Ok(json) => json,
            Err(_) => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        (OK_RESPONSE.to_string(), response_json)
    }

    pub async fn create_role(
        &self,
        rp_svc: &Arc<RolePermissionSvc<DB>>,
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
        let req_role: CreateRole = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };

        let new_role = Role {
            name: req_role.name,
            role_id: None,
            description: req_role.description,
            created_at: Utc::now(),
        };
        let new_role_id = match self.repository.insert_role(&new_role).await {
            Ok(new_role_id) => new_role_id,
            Err(err) => match err {
                CustomError::RoleExists => {
                    eprintln!("Error insert: {:#?}", err);
                    return (BAD_REQUEST.to_string(), "Already registered".to_string());
                }
                error => {
                    eprintln!("Error insert role db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };
        return rp_svc
            .insert_role_permissions(new_role_id, req_role.permissions)
            .await;
    }
}
