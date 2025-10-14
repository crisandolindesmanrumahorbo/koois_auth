use crate::auth::service::AuthService;
use crate::cfg::CONFIG;
use crate::constants::NOT_FOUND;
use crate::db::DBConn;
use crate::google::GoogleTokenVerifier;
use crate::mdw::Middleware;
use crate::permission::service::PermissionSvc;
use crate::role::service::RoleSvc;
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
    role_svc: Arc<RoleSvc<DB>>,
    go_ver: Arc<GoogleTokenVerifier>,
}

impl<DB> Server<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        let auth_svc = Arc::new(AuthService::new(pool.clone()));
        let permission_svc = Arc::new(PermissionSvc::new(pool.clone()));
        let role_svc = Arc::new(RoleSvc::new(pool.clone()));
        let rp_svc = Arc::new(RolePermissionSvc::new(pool));
        let go_ver = Arc::new(GoogleTokenVerifier::new(CONFIG.google_client_id.clone()));

        Self {
            auth_svc,
            rp_svc,
            permission_svc,
            role_svc,
            go_ver,
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
                    let role_svc = Arc::clone(&self.role_svc);
                    let go_ver = Arc::clone(&self.go_ver);

                    tokio::spawn(async move {
                        if let Err(e) = Server::handle_client(stream, &auth_svc, &rp_svc, &permission_svc, &role_svc, &go_ver).await {
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
        role_svc: &Arc<RoleSvc<DB>>,
        go_ver: &Arc<GoogleTokenVerifier>,
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
            (Method::POST, "/reset-password") => auth_svc.reset_password(&request).await,
            (Method::POST, "/forgot-password") => auth_svc.forgot_password(&request).await,
            (Method::POST, "/signin-google") => auth_svc.signin_google(&request, &go_ver).await,
            (Method::POST, "/register-google") => auth_svc.register_google(&request, &go_ver).await,
            (Method::GET, "/protected/validate") => auth_svc.validate(&request),
            (Method::GET, "/protected/user/role-permissions") => {
                rp_svc.get_role_permissions_by_role_id(claims).await
            }
            (Method::GET, "/protected/user/permissions") => permission_svc.get_permissions().await,
            (Method::POST, "/protected/user/permissions") => {
                permission_svc.create_permission(claims, &request).await
            }
            (Method::POST, "/protected/user/roles") => {
                role_svc.create_role(&rp_svc, claims, &request).await
            }
            (Method::GET, "/protected/user/roles") => role_svc.get_roles(claims).await,

            _ => (NOT_FOUND.to_string(), "404 Not Found".to_string()),
        };

        writer
            .write_all(format!("{}{}", status_line, content).as_bytes())
            .await
            .context("Failed to write")
    }
}
