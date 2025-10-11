#[derive(Debug, sqlx::FromRow)]
pub struct RolePermissions {
    pub role_id: i32,
    pub permission_id: i32,
}
