use super::{
    model::{ForgotPassword, LoginRegister, RegisterGoogle, ResetPassword, SigninGoogle},
    repo::AuthRepository,
};
use crate::{
    auth::model::Login,
    constants::{
        BAD_REQUEST, GOOGLE, INTERNAL_ERROR, LOCAL, NO_CONTENT, OK_RESPONSE, UNAUTHORIZED,
    },
    db::DBConn,
    error::CustomError,
    google::GoogleTokenVerifier,
    mail::{Attribs, ForgotPasswordMail, Mail},
    utils::{
        ClaimType, create_jwt, des_from_str, encrypt, extract_token, is_password_valid, ser_to_str,
        verify_jwt,
    },
};
use chrono::Utc;
use request_http_parser::parser::Request;
use std::sync::Arc;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Response {
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct ResponseSignGoogle {
    pub token: Option<String>,
    pub is_registered: bool,
}

pub struct AuthService<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    repository: AuthRepository<DB>,
}

impl<DB> AuthService<DB>
where
    DB: DBConn + Send + Sync + 'static,
{
    pub fn new(pool: DB) -> Self {
        AuthService {
            repository: AuthRepository::new(pool),
        }
    }

    pub async fn login(&self, request: &Request) -> (String, String) {
        self.repository.print_pool_stats();

        let req_user: Login = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };
        let user_db = match self.repository.query_user(&req_user.username).await {
            Ok(user) => user,
            Err(why) => match why {
                CustomError::UserNotFound => {
                    println!("User {} not found", req_user.username);
                    return (UNAUTHORIZED.to_string(), "".to_string());
                }
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };

        let password = match &user_db.password {
            Some(body) => body,
            None => return (UNAUTHORIZED.to_string(), "".to_string()),
        };

        if !is_password_valid(&req_user.password, password) {
            println!("User {} wrong password", req_user.username);
            return (
                UNAUTHORIZED.to_string(),
                "Username or password is incorrect".to_string(),
            );
        }

        let token = match create_jwt(&user_db, ClaimType::Login) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("Error creating JWT: {:#?}", e);
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        let response = Response { token };
        let response_json = match ser_to_str(&response) {
            Ok(json) => json,
            Err(_) => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        println!("{} succeed login", req_user.username);
        (OK_RESPONSE.to_string(), response_json)
    }

    pub async fn register(&self, request: &Request) -> (String, String) {
        let req_user: LoginRegister = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };

        if req_user.password.is_empty() {
            return (BAD_REQUEST.to_string(), "".to_string());
        }

        let new_user = super::model::User {
            username: req_user.username,
            password: Some(encrypt(&req_user.password)),
            user_id: None,
            role_id: req_user.role_id,
            created_at: Utc::now(),
            email: None,
            provider: LOCAL.to_string(),
            provider_id: None,
        };
        match self.repository.insert_user(&new_user).await {
            Ok(_) => (NO_CONTENT.to_string(), "".to_string()),
            Err(err) => match err {
                CustomError::UsernameExists => {
                    eprintln!("Error insert: {:#?}", err);
                    (BAD_REQUEST.to_string(), "Already registered".to_string())
                }
                error => {
                    eprintln!("Error insert user db: {:#?}", error);
                    (INTERNAL_ERROR.to_string(), "".to_string())
                }
            },
        }
    }

    pub async fn forgot_password(&self, request: &Request) -> (String, String) {
        let req_user: ForgotPassword = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };
        let user_db = match self.repository.query_user(&req_user.username).await {
            Ok(user) => user,
            Err(why) => match why {
                CustomError::UserNotFound => {
                    println!("User {} not found", req_user.username);
                    return (UNAUTHORIZED.to_string(), "".to_string());
                }
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };

        let user_email = match &user_db.email {
            Some(email) => email.to_string(),
            None => {
                eprintln!("Cannot forgot password caused no email");
                return (BAD_REQUEST.to_string(), "You have no email".to_string());
            }
        };
        let token = match create_jwt(&user_db, ClaimType::ForgotPassword) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("Error creating JWT: {:#?}", e);
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        let response = Response {
            token: token.clone(),
        };
        let response_json = match ser_to_str(&response) {
            Ok(json) => json,
            Err(_) => {
                println!("serde error");
                return (INTERNAL_ERROR.to_string(), "".to_string());
            }
        };
        println!("{} succeed login", req_user.username);
        let reset_email = ForgotPasswordMail {
            recipient: user_email,
            addresser: String::from("noreply@koois.id"),
            attribs: Attribs {
                reset_link: format!("http://localhost:3000/en/reset-password?token={}", token)
                    .to_string(),
            },
        };
        let _ = Mail::send_email(reset_email).await;
        (OK_RESPONSE.to_string(), response_json)
    }

    pub async fn reset_password(&self, request: &Request) -> (String, String) {
        let reset_password: ResetPassword = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };
        let claims = match verify_jwt(&reset_password.token) {
            Ok(claims) => claims,
            Err(err) => {
                println!("Verification failed: {}", err);
                return (UNAUTHORIZED.to_string(), "".to_string());
            }
        };
        if claims.claim_type == ClaimType::Login {
            return (UNAUTHORIZED.to_string(), "".to_string());
        }
        let new_password = encrypt(&reset_password.password);

        match self
            .repository
            .update_password(&claims.sub, &new_password)
            .await
        {
            Ok(_) => (OK_RESPONSE.to_string(), "".to_string()),
            Err(err) => match err {
                error => {
                    eprintln!("Error insert user db: {:#?}", error);
                    (INTERNAL_ERROR.to_string(), "".to_string())
                }
            },
        }
    }

    pub fn validate(&self, request: &Request) -> (String, String) {
        let token = match extract_token(&request.headers) {
            Some(token) => token,
            None => {
                println!("Missing Header");
                return (UNAUTHORIZED.to_string(), "".to_string());
            }
        };

        match verify_jwt(&token) {
            Ok(_) => (OK_RESPONSE.to_string(), "".to_string()),
            Err(err) => {
                println!("Verification failed: {}", err);
                (UNAUTHORIZED.to_string(), "".to_string())
            }
        }
    }

    pub async fn signin_google(
        &self,
        request: &Request,
        go_ver: &Arc<GoogleTokenVerifier>,
    ) -> (String, String) {
        let signin_goole: SigninGoogle = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };
        let google_data = match go_ver.verify(&signin_goole.token).await {
            Ok(payload) => {
                println!("✓ Token valid");
                println!("User ID: {}", payload.sub);
                println!("Email: {:?}", payload.email);
                payload
            }
            Err(e) => {
                println!("✗ Token invalid: {}", e);
                return (BAD_REQUEST.to_string(), "token invalid".to_string());
            }
        };
        let user_db = match self.repository.query_user(&google_data.email).await {
            Ok(user) => Some(user),
            Err(why) => match why {
                CustomError::UserNotFound => {
                    println!("User {} not found", google_data.email);
                    None
                }
                error => {
                    eprintln!("Error user db: {:#?}", error);
                    return (INTERNAL_ERROR.to_string(), "".to_string());
                }
            },
        };

        match user_db {
            Some(user) => {
                let token = match create_jwt(&user, ClaimType::Login) {
                    Ok(token) => token,
                    Err(e) => {
                        eprintln!("Error creating JWT: {:#?}", e);
                        return (INTERNAL_ERROR.to_string(), "".to_string());
                    }
                };
                let response = ResponseSignGoogle {
                    token: Some(token),
                    is_registered: true,
                };
                let response_json = match ser_to_str(&response) {
                    Ok(json) => json,
                    Err(_) => {
                        println!("serde error");
                        return (INTERNAL_ERROR.to_string(), "".to_string());
                    }
                };
                println!("{} succeed login", user.username);
                return (OK_RESPONSE.to_string(), response_json);
            }
            None => {
                let response = ResponseSignGoogle {
                    token: None,
                    is_registered: false,
                };
                let response_json = match ser_to_str(&response) {
                    Ok(json) => json,
                    Err(_) => {
                        println!("serde error");
                        return (INTERNAL_ERROR.to_string(), "".to_string());
                    }
                };
                return (OK_RESPONSE.to_string(), response_json);
            }
        }
    }

    pub async fn register_google(
        &self,
        request: &Request,
        go_ver: &Arc<GoogleTokenVerifier>,
    ) -> (String, String) {
        let register_google: RegisterGoogle = match &request.body {
            Some(body) => match des_from_str(body) {
                Ok(user) => user,
                Err(_) => return (BAD_REQUEST.to_string(), "".to_string()),
            },
            None => return (BAD_REQUEST.to_string(), "".to_string()),
        };
        let google_data = match go_ver.verify(&register_google.token).await {
            Ok(payload) => {
                println!("✓ Token valid");
                println!("User ID: {}", payload.sub);
                println!("Email: {:?}", payload.email);
                payload
            }
            Err(e) => {
                println!("✗ Token invalid: {}", e);
                return (BAD_REQUEST.to_string(), "token invalid".to_string());
            }
        };
        let new_user = super::model::User {
            username: google_data.email.clone(),
            password: None,
            user_id: None,
            role_id: register_google.role_id,
            created_at: Utc::now(),
            email: Some(google_data.email),
            provider: GOOGLE.to_string(),
            provider_id: Some(google_data.sub),
        };
        match self.repository.insert_user(&new_user).await {
            Ok(_) => (NO_CONTENT.to_string(), "".to_string()),
            Err(err) => match err {
                CustomError::UsernameExists => {
                    eprintln!("Error insert: {:#?}", err);
                    (BAD_REQUEST.to_string(), "Already registered".to_string())
                }
                error => {
                    eprintln!("Error insert user db: {:#?}", error);
                    (INTERNAL_ERROR.to_string(), "".to_string())
                }
            },
        }
    }
}
