use std::{error::Error, fmt::Debug};

#[derive(thiserror::Error)]
pub enum CustomError {
    #[error("ENV '{0}' Not Found")]
    EnvError(String, #[source] std::env::VarError),

    #[error("Error encode private key")]
    EncodeError(#[source] jsonwebtoken::errors::Error),

    #[error("Database error")]
    DBError(#[from] sqlx::Error),

    #[error("User not found")]
    UserNotFound,

    #[error("Username already exists")]
    UsernameExists,

    #[error("Account already exists")]
    AccountExists,

    #[error("Role not found")]
    RoleNotFound,

    #[error("Permission already exists")]
    PermissionExists,

    #[error("Role already exists")]
    RoleExists,

    #[error("Role Permission already exists")]
    RolePermissionExists,
}

impl Debug for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;
        if let Some(source) = self.source() {
            write!(f, " (Caused by: {})", source)?;
        }
        Ok(())
    }
}
