use super::model::GetUsers;
use crate::{db::DBConn, error::CustomError};

pub struct UserRepository<DB: DBConn> {
    db: DB,
}

impl<DB: DBConn> UserRepository<DB> {
    pub fn new(db: DB) -> Self {
        UserRepository { db }
    }

    pub async fn fetch_users(&self) -> Result<Vec<GetUsers>, CustomError> {
        self.db.fetch_users().await.map_err(|e| match e {
            _ => CustomError::DBError(e),
        })
    }
}
