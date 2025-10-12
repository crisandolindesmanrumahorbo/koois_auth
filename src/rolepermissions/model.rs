#[derive(Debug, sqlx::FromRow)]
pub struct RolePermissions {
    pub role_id: i32,
    pub permission_id: i32,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct GetRolePermissions {
    pub name: String,
}
