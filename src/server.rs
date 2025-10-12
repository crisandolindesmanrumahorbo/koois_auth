use crate::auth::service::AuthService;
use crate::constants::NOT_FOUND;
use crate::db::DBConn;
use crate::mdw::Middleware;
use crate::permission::service::PermissionSvc;
use crate::rolepermissions::service::RolePermissionSvc;
use anyhow::{Context, Result};
use request_http_parser::parser::Method;

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot::Receiver;

pub struct Server<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    auth_svc: Arc<AuthService<DB>>,
    rp_svc: Arc<RolePermissionSvc<DB>>,
    permission_svc: Arc<PermissionSvc<DB>>,
}

impl<DB> Server<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        let auth_svc = Arc::new(AuthService::new(pool.clone()));
        let permission_svc = Arc::new(PermissionSvc::new(pool.clone()));
        let rp_svc = Arc::new(RolePermissionSvc::new(pool));
        Self {
            auth_svc,
            rp_svc,
            permission_svc,
        }
    }

    pub async fn start(&self, mut shutdown_rx: Receiver<()>) -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:7879")
            .await
            .expect("failed to binding port");
        println!("Server running on http://127.0.0.1:7879");

        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (stream, _) = conn?;

                    let auth_svc = Arc::clone(&self.auth_svc);
                    let rp_svc = Arc::clone(&self.rp_svc);
                    let permission_svc = Arc::clone(&self.permission_svc);

                    tokio::spawn(async move {
                        if let Err(e) = Server::handle_client(stream, &auth_svc, &rp_svc, &permission_svc).await {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                // Shutdown signal check
                _ = &mut shutdown_rx => {
                    println!("Shutting down server...");
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn handle_client(
        mut stream: TcpStream,
        auth_svc: &Arc<AuthService<DB>>,
        rp_svc: &Arc<RolePermissionSvc<DB>>,
        permission_svc: &Arc<PermissionSvc<DB>>,
    ) -> Result<()> {
        let (request, claims) = match Middleware::new(&mut stream).await {
            Ok((request, user_id)) => (request, user_id),
            Err(e) => {
                println!("{:?}", e);
                return Ok(());
            }
        };
        let (_, mut writer) = stream.split();

        // Route
        let (status_line, content) = match (&request.method, request.path.as_str()) {
            (Method::POST, "/login") => auth_svc.login(&request).await,
            (Method::POST, "/register") => auth_svc.register(&request).await,
            (Method::GET, "/protected/validate") => auth_svc.validate(&request),
            (Method::GET, "/protected/user/role-permissions") => {
                rp_svc.get_role_permissions_by_role_id(claims).await
            }
            (Method::GET, "/protected/user/permissions") => permission_svc.get_permissions().await,
            (Method::POST, "/protected/user/permissions") => {
                permission_svc.create_permission(claims, &request).await
            }

            _ => (NOT_FOUND.to_string(), "404 Not Found".to_string()),
        };

        writer
            .write_all(format!("{}{}", status_line, content).as_bytes())
            .await
            .context("Failed to write")
    }
}
