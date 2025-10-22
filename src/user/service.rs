use super::repo::UserRepository;
use crate::{
    constants::{INTERNAL_ERROR, OK_RESPONSE},
    db::DBConn,
    utils::{Claims, ser_to_str},
};

pub struct UserSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    repository: UserRepository<DB>,
}

impl<DB> UserSvc<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        UserSvc {
            repository: UserRepository::new(pool),
        }
    }

    pub async fn get_users(&self, _claims: Option<Claims>) -> (String, String) {
        // only manages users can get all permission
        let users = match self.repository.fetch_users().await {
            Ok(user) => user,
            Err(why) => match why {
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };
        let response_json = match ser_to_str(&users) {
            Ok(json) => json,
            Err(_) => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        (OK_RESPONSE.to_string(), response_json)
    }
}
