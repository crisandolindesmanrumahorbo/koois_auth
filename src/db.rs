use crate::auth::model::User;
use crate::rolepermissions::model::GetRolePermissions;
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
    async fn fetch_permissions(&self, role_id: i32)
    -> Result<Vec<GetRolePermissions>, sqlx::Error>;

    fn print_pool_stats(&self);
}

#[async_trait]
impl DBConn for sqlx::PgPool {
    async fn fetch_user(&self, username: &str) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"SELECT user_id, username, password, role_id, created_at FROM users WHERE username = $1"#,
        )
        .bind(username)
        .fetch_one(self)
        .await
    }
    async fn insert_user(&self, user: &User) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            INSERT INTO users (username, password, role_id, created_at) 
            VALUES ($1, $2, $3, $4) 
            RETURNING user_id"#,
        )
        .bind(&user.username)
        .bind(&user.password)
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

    async fn fetch_permissions(
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
}
