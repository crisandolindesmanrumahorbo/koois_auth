use crate::auth::model::User;
use crate::permission::model::Permission;
use crate::role::model::Role;
use crate::rolepermissions::model::GetRolePermissions;
use crate::user::model::GetUsers;
use async_trait::async_trait;
use sqlx::Pool;
use sqlx::postgres::PgPoolOptions;

pub struct Database {
    pub pool: Pool<sqlx::Postgres>,
}

impl Database {
    pub async fn new_pool(url: &str) -> Pool<sqlx::Postgres> {
        PgPoolOptions::new()
            .max_connections(10)
            .min_connections(5)
            .idle_timeout(std::time::Duration::from_secs(30))
            .connect(url)
            .await
            .expect("Failed to create DB pool")
    }
}

#[async_trait]
pub trait DBConn: Send + Sync + Clone {
    async fn fetch_user(&self, username: &str) -> Result<User, sqlx::Error>;
    async fn insert_user(&self, user: &User) -> Result<i32, sqlx::Error>;
    async fn insert_role(&self, role: &Role) -> Result<i32, sqlx::Error>;
    async fn fetch_roles(&self) -> Result<Vec<Role>, sqlx::Error>;
    async fn fetch_role_permissions(
        &self,
        role_id: i32,
    ) -> Result<Vec<GetRolePermissions>, sqlx::Error>;
    async fn fetch_permissions(&self) -> Result<Vec<Permission>, sqlx::Error>;
    async fn insert_permission(&self, permission: &Permission) -> Result<i32, sqlx::Error>;
    async fn insert_permission_role(
        &self,
        role_id: i32,
        permission_ids: Vec<i32>,
    ) -> Result<(), sqlx::Error>;
    async fn update_password(&self, user_id: &str, password: &str) -> Result<i32, sqlx::Error>;
    fn print_pool_stats(&self);
    async fn fetch_users(&self) -> Result<Vec<GetUsers>, sqlx::Error>;
}

#[async_trait]
impl DBConn for sqlx::PgPool {
    async fn fetch_user(&self, username: &str) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"SELECT user_id, username, password, email, provider, provider_id, role_id, created_at FROM users WHERE username = $1"#,
        )
        .bind(username)
        .fetch_one(self)
        .await
    }
    async fn insert_user(&self, user: &User) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            INSERT INTO users (username, password, email, provider, provider_id, role_id, created_at) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING user_id"#,
        )
        .bind(&user.username)
        .bind(&user.password)
        .bind(&user.email)
        .bind(&user.provider)
        .bind(&user.provider_id)
        .bind(&user.role_id)
        .bind(&user.created_at)
        .fetch_one(self)
        .await?;
        Ok(row.0)
    }

    fn print_pool_stats(&self) {
        println!("[DB POOL STATS]");
        println!("Total connections: {}", self.size());
        println!("Idle connections: {}", self.num_idle());
        println!(
            "Active connections: {}",
            self.size() - self.num_idle() as u32
        );
    }

    async fn fetch_role_permissions(
        &self,
        role_id: i32,
    ) -> Result<Vec<GetRolePermissions>, sqlx::Error> {
        sqlx::query_as::<_, GetRolePermissions>(
            r#"SELECT p.name
            FROM permissions p
            JOIN role_permissions rp ON p.permission_id = rp.permission_id
            WHERE rp.role_id = $1"#,
        )
        .bind(role_id)
        .fetch_all(self)
        .await
    }

    async fn fetch_permissions(&self) -> Result<Vec<Permission>, sqlx::Error> {
        sqlx::query_as::<_, Permission>(
            r#"SELECT permission_id, name, description, created_at
            FROM permissions"#,
        )
        .fetch_all(self)
        .await
    }

    async fn insert_permission(&self, permission: &Permission) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            INSERT INTO permissions (name, description, created_at) 
            VALUES ($1, $2, $3) 
            RETURNING permission_id"#,
        )
        .bind(&permission.name)
        .bind(&permission.description)
        .bind(&permission.created_at)
        .fetch_one(self)
        .await?;
        Ok(row.0)
    }

    async fn insert_role(&self, role: &Role) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            INSERT INTO roles (name, description, created_at) 
            VALUES ($1, $2, $3) 
            RETURNING role_id"#,
        )
        .bind(&role.name)
        .bind(&role.description)
        .bind(&role.created_at)
        .fetch_one(self)
        .await?;
        Ok(row.0)
    }

    async fn fetch_roles(&self) -> Result<Vec<Role>, sqlx::Error> {
        sqlx::query_as::<_, Role>(
            r#"SELECT role_id, name, description, created_at
            FROM roles"#,
        )
        .fetch_all(self)
        .await
    }

    async fn insert_permission_role(
        &self,
        role_id: i32,
        permission_ids: Vec<i32>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT $1, UNNEST($2::int[])
            "#,
        )
        .bind(role_id)
        .bind(&permission_ids)
        .execute(self)
        .await?;
        Ok(())
    }

    async fn update_password(&self, user_id: &str, password: &str) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            UPDATE users
            SET password = $1 
            WHERE user_id = $2
            RETURNING user_id"#,
        )
        .bind(password)
        .bind(user_id.parse::<i32>().expect("Failed to parse to i32"))
        .fetch_one(self)
        .await?;
        Ok(row.0)
    }

    async fn fetch_users(&self) -> Result<Vec<GetUsers>, sqlx::Error> {
        sqlx::query_as::<_, GetUsers>(
            r#"SELECT user_id, username, email, provider, role_id, created_at
            FROM users"#,
        )
        .fetch_all(self)
        .await
    }
}
