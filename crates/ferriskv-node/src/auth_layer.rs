use std::sync::Arc;

use ferriskv_auth::{Claims, JwtVerifier};
use tonic::service::Interceptor;
use tonic::{Request, Status};

#[derive(Debug, Clone)]
pub enum Principal {
    Anonymous,
    Authenticated(Arc<Claims>),
}

impl Principal {
    pub fn tenant(&self) -> Option<&str> {
        match self {
            Principal::Anonymous => None,
            Principal::Authenticated(c) => Some(c.tenant.as_ref()),
        }
    }

    pub fn allows(&self, perm: &str) -> bool {
        match self {
            Principal::Anonymous => true,
            Principal::Authenticated(c) => c.allows(perm),
        }
    }
}

#[derive(Clone)]
pub struct AuthInterceptor {
    verifier: Option<Arc<JwtVerifier>>,
    insecure: bool,
}

impl AuthInterceptor {
    pub fn insecure() -> Self {
        Self {
            verifier: None,
            insecure: true,
        }
    }

    pub fn with_verifier(verifier: Arc<JwtVerifier>) -> Self {
        Self {
            verifier: Some(verifier),
            insecure: false,
        }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if self.insecure {
            req.extensions_mut().insert(Principal::Anonymous);
            return Ok(req);
        }

        let verifier = self
            .verifier
            .as_ref()
            .ok_or_else(|| Status::internal("auth misconfigured: no verifier"))?;

        let header = req
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;

        let raw = header
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization header is not ASCII"))?;

        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .ok_or_else(|| Status::unauthenticated("authorization must start with Bearer"))?;

        let claims = verifier
            .verify(token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))?;

        req.extensions_mut()
            .insert(Principal::Authenticated(Arc::new(claims)));
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferriskv_auth::Claims;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn make_token(secret: &[u8], tenant: &str, perms: &[&str]) -> String {
        let claims = Claims {
            sub: Arc::<str>::from("u1"),
            tenant: Arc::<str>::from(tenant),
            roles: Vec::new(),
            perms: perms.iter().map(|p| Arc::<str>::from(*p)).collect(),
            exp: now() + 3600,
            iss: None,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn req_with_header(value: &str) -> Request<()> {
        let mut r = Request::new(());
        r.metadata_mut()
            .insert("authorization", value.parse().unwrap());
        r
    }

    #[test]
    fn insecure_inserts_anonymous_principal() {
        let mut int = AuthInterceptor::insecure();
        let req = int.call(Request::new(())).unwrap();
        let p = req.extensions().get::<Principal>().unwrap();
        assert!(matches!(p, Principal::Anonymous));
    }

    #[test]
    fn missing_header_is_unauthenticated() {
        let v = Arc::new(JwtVerifier::new_hs256(b"secret"));
        let mut int = AuthInterceptor::with_verifier(v);
        let err = int.call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn bad_scheme_is_unauthenticated() {
        let v = Arc::new(JwtVerifier::new_hs256(b"secret"));
        let mut int = AuthInterceptor::with_verifier(v);
        let err = int.call(req_with_header("Basic abc")).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn valid_token_inserts_authenticated_principal() {
        let secret = b"hunter2";
        let token = make_token(secret, "alice", &["read", "write"]);
        let v = Arc::new(JwtVerifier::new_hs256(secret));
        let mut int = AuthInterceptor::with_verifier(v);
        let req = int.call(req_with_header(&format!("Bearer {token}"))).unwrap();
        let p = req.extensions().get::<Principal>().unwrap();
        match p {
            Principal::Authenticated(c) => {
                assert_eq!(c.tenant.as_ref(), "alice");
                assert!(c.allows("read"));
                assert!(c.allows("write"));
                assert!(!c.allows("delete"));
            }
            Principal::Anonymous => panic!("expected authenticated"),
        }
    }

    #[test]
    fn admin_perm_implies_all() {
        let secret = b"hunter2";
        let token = make_token(secret, "alice", &["admin"]);
        let v = Arc::new(JwtVerifier::new_hs256(secret));
        let mut int = AuthInterceptor::with_verifier(v);
        let req = int.call(req_with_header(&format!("Bearer {token}"))).unwrap();
        let p = req.extensions().get::<Principal>().unwrap();
        assert!(p.allows("read"));
        assert!(p.allows("write"));
        assert!(p.allows("delete"));
        assert!(p.allows("watch"));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let token = make_token(b"secret-a", "alice", &["read"]);
        let v = Arc::new(JwtVerifier::new_hs256(b"secret-b"));
        let mut int = AuthInterceptor::with_verifier(v);
        let err = int.call(req_with_header(&format!("Bearer {token}"))).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
