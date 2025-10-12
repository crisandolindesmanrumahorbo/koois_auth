use super::model::User;
use crate::{db::DBConn, error::CustomError};

pub struct AuthRepository<DB: DBConn> {
    db: DB,
}

impl<DB: DBConn> AuthRepository<DB> {
    pub fn new(db: DB) -> Self {
        AuthRepository { db }
    }

    pub fn print_pool_stats(&self) {
        self.db.print_pool_stats();
    }

    pub async fn query_user(&self, username: &str) -> Result<User, CustomError> {
        self.db.fetch_user(username).await.map_err(|e| match e {
            sqlx::Error::RowNotFound => CustomError::UserNotFound,
            _ => CustomError::DBError(e),
        })
    }

    pub async fn insert_user(&self, new_user: &User) -> Result<i32, CustomError> {
        let user_id = match self.db.insert_user(new_user).await {
            Ok(user_id) => user_id,
            Err(e) => match e {
                sqlx::Error::Database(err) if err.is_unique_violation() => {
                    return Err(CustomError::UsernameExists);
                }
                _ => return Err(CustomError::DBError(e)),
            },
        };
        Ok(user_id)
    }
}
