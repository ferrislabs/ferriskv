pub mod api_key;
pub mod jwt;
pub mod rbac;

pub use api_key::{ApiKey, ApiKeyStore};
pub use jwt::{Claims, JwtVerifier};
pub use rbac::{Permission, Role, RoleSet};

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("expired token")]
    Expired,

    #[error("forbidden: missing {0:?}")]
    Forbidden(Permission),

    #[error("unknown api key")]
    UnknownApiKey,

    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub type Result<T, E = AuthError> = std::result::Result<T, E>;
