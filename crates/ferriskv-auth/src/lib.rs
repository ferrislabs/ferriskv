pub mod api_key;
pub mod jwks;
pub mod jwt;
pub mod rbac;

pub use api_key::{ApiKey, ApiKeyStore};
pub use jwks::{KeyRing, SharedKeyRing, SkippedKey};
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

    #[error("token carries no kid, required when keys come from a JWKS")]
    MissingKid,

    #[error("no verification key for kid {0}")]
    UnknownKid(String),

    #[error("jwks: {0}")]
    Jwks(String),

    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub type Result<T, E = AuthError> = std::result::Result<T, E>;

/// A fixed RSA keypair, so signature tests exercise real verification without
/// generating a key per run.
///
/// Published in a public repository on purpose: these keys secure nothing, and
/// the alternative — a keygen dependency in dev-dependencies — buys no safety
/// for a value that is a test fixture either way.
#[cfg(test)]
pub(crate) mod test_keys {
    pub const JWK_E: &str = "AQAB";

    pub const JWK_N_A: &str = "pURFKodLI8fzKTrP8X11yT6HfqbCfkcAbpy7hDdeQd4jau5L6Fi1punF66nScZIwCYVdpSqTd_DDlBQH2sWtg7wRZb_gkcPwRAkOH16zSaEooZVYX_bRY1oV0167w6AOjkze7DeFsmMf-Akh0vRQLRzWRNdM48qRPZmXrS9v7cy-KkwCGibv6PI-Vw94izDTbwrqqYfdCrqR6GRVC0pZHOjpMMvAWukCstjYdCJTaChqbzgk1uCKOA_cwNWj9mtpyG2cTkpBsB68U2NwMsJOjFpGCO6ZI5tc283AnNEbyiSGk3jeST2uOl4g3TJWp6QC_9r2A0iRjK6SBRkPgVevnw";

    pub const PEM_A: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClREUqh0sjx/Mp
Os/xfXXJPod+psJ+RwBunLuEN15B3iNq7kvoWLWm6cXrqdJxkjAJhV2lKpN38MOU
FAfaxa2DvBFlv+CRw/BECQ4fXrNJoSihlVhf9tFjWhXTXrvDoA6OTN7sN4WyYx/4
CSHS9FAtHNZE10zjypE9mZetL2/tzL4qTAIaJu/o8j5XD3iLMNNvCuqph90KupHo
ZFULSlkc6Okwy8Ba6QKy2Nh0IlNoKGpvOCTW4Io4D9zA1aP2a2nIbZxOSkGwHrxT
Y3Aywk6MWkYI7pkjm1zbzcCc0RvKJIaTeN5JPa46XiDdMlanpAL/2vYDSJGMrpIF
GQ+BV6+fAgMBAAECggEAAbXOQ4qxkuP6vj5ru9vx+J1TrjQ/Ne59kphk9j4tnGda
ApeOr4gQpdwsYDO/+NwRhxIMLHEySdG+SgQMOXdFnpEReQUTHF4ZWHRM8hygs9t4
EpRz79b9e5Z6S3V5j5VSfIg/7ok/m7Iyi5we72ysnZrkup1JY/4OsWjJiRT10hU9
9zmcU2Ya8k0fgRu+A35KXMKQuCON3bVCDW2Fc5Xk8YSqvrVW3x783WlUJae9b0pK
+pgR9Gveu5ByspgwSoWna2Y9PMWDQ0aCpNr2de+gp1kiTSi+8zyfYeCR1RKLRGb9
go7aFJ8eIVK4vgCAl0mF66KGRUfyfXXVg8maNZqCYQKBgQDlUV1KmiXEuL9/f/zD
1r1EaJO02LHXvPbAzoJBr1OqK80ZxCrzABqYr5q2grGsiZKnx4AmqK0ZGTiyM2sK
5sKfnVjPQ6rBCBBlOqVrs+5Sce/BLUAOTtzTH3Vkg2P025bdf8Y4FUI8icTFGJCk
VtBJAcFiLcQ+x0FdJ6wSt9OG0QKBgQC4fweIpObb2iwoSuOyToFKl806hhoqZeCB
0KgqnKB79YqOwVoxnRMIUOL+J6meJ11H1pjPV63dpj6FFnxQ8BrPxBcz9QBCKcBj
Gszi9blcTcocKZpiKIHGGYjxUWViqTirzQ+OwO43A3qrO461qMgrERhCNzmUTKSY
SSn5bFFLbwKBgD5mEnWfVlGeV/VwtS3w+9Vmg3K9WD81GwvB5a3L8H8opgmx2GIB
EDul5Ppuu7wQP0jKP3PFiDyBIW1UEneH7UOThDv51Lfr4tI40BRrhJkIic3N61U5
XltQfxgXrJZPPlENWLmgB0MD1fgvxAQD329OO/nkLDdM7ttTVT5OqQ9RAoGBAIxI
ysmz2XZCJmFc0FW8K8M0OfDOFwc1/8e1iKkd/0lCIuD5VEN1VAt2taLbNbXz6JG/
MuI1oRZwWgmIV26To09notz25gNpC8hPkIrinNb6rztKxwDsHAEtWVtksNqcIWNA
wRuix389PgEFgDXQ6KMWlIOEylthC6Zfu3LUUdwxAoGAa7tcwgGWunzmV0B/qpU9
oZwfIrulECjUTWOBLGV9qR4WXd5mq6wvJ+XcSxXOLOR75B3f7RRLcfvK6Qr7e0oR
GNTpzAl7/nIQ5gmPP+wEUrFXIp68sRlMtW7SgUjDCU7b/osH9g85UiUUND6R+z8m
cNTpN4eA0LgKP0usHH1Ag9Q=
-----END PRIVATE KEY-----
"#;

    pub const JWK_N_B: &str = "6bE_ESlcjP-bscRbq8HU9vrg3_dIgT3YrxwHf0cDaHQ6Wk1qD6douWx3hHg-GvXeO3JteTiNzUSItaR1RIqHfuaDh-pTWlk_TOs_pzbJa4bckXhuMiEAneL44MKZPfKOzWXLvDkY1BAdg8VDyO7CbyXkQIfLwzHfkSuRVj8E2DVn3pl3JdFe7sb7BRRqjmJDZ9Nz-HA9mBFzmG2D_U_zEu4J5UgM3ek64vDjuOgoDLRidFQX2JO-4EPKaVWjYm7AlbOVbwzuyhWrjvopsemI8naMmYDdathEmLjE1-EROE9b45u002MKo_0U2F4JDBZlIoA5vR2LvYrBJFFWayiOBQ";

    pub const PEM_B: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDpsT8RKVyM/5ux
xFurwdT2+uDf90iBPdivHAd/RwNodDpaTWoPp2i5bHeEeD4a9d47cm15OI3NRIi1
pHVEiod+5oOH6lNaWT9M6z+nNslrhtyReG4yIQCd4vjgwpk98o7NZcu8ORjUEB2D
xUPI7sJvJeRAh8vDMd+RK5FWPwTYNWfemXcl0V7uxvsFFGqOYkNn03P4cD2YEXOY
bYP9T/MS7gnlSAzd6Tri8OO46CgMtGJ0VBfYk77gQ8ppVaNibsCVs5VvDO7KFauO
+imx6YjydoyZgN1q2ESYuMTX4RE4T1vjm7TTYwqj/RTYXgkMFmUigDm9HYu9isEk
UVZrKI4FAgMBAAECggEAGdYIOG//tPDveCRS1DbeQh3zbZ9rqyo4wgdRxt8Ff+9V
ojUr1CY4fEODJSicCSQEmULp2nyHpNl+WcKgWl8MYtm+UfD0nSj/yBO8GlMCyroC
uax8Vltys4Hr7QFmqsQdyJSIBTu0xIExmiddeqH26g3g4ceBngduBaEw9L2L3hE3
WbnPySz1syHa99GEIZFtmuOECh2xyIWSsim3S310TPiEWPhJwOxWxwSvM/YiMXSr
QRCYvhB9yxR8M97m/zJoQouAD/Ba+xi0X2YScqb1aLlR0CVHOmpkA7GVkKAoJuWc
lI+s9sdnSBcD15Qo1D8n2hnbwmh9fXMWXKN5lb6RYQKBgQD8jelXxIYADSxAQv78
ujLVqDXoiNQkqg/I+kEuE8JIxU3wQNmeWS0u9bUjt0AZk8UgQhUO8pL5NG0hKuHs
0ygFzVnB/kKtrYlO7e66BOjKiTyJJ8KR7NjCFJePtNzz0HzFhc1orUWyqW0xxVry
jOLB8xNTEyEC77hbapU/MTywUQKBgQDs4XTMnVnBWVx4c3PJH91ql70ZU2N/ppHZ
jGd3NKk20oQ6u0BQsMpm7hUtUcKxDPtRL8K1ESKtsh4p5NP2gfEV8QtibrVXKRo0
T7GuFRPSMM+AxOUGBabzszliJIcL5YIDTrE31Z1eNxNlaWZATFvuL8Vy2mIDJOVA
+NOGmn8pdQKBgFVNuZsjjf9Gc8Pg3S+P1MvF3S+Fx+H6bwp7PLjLg7wAqKqVvOt3
Q4OxClXd95CsENEsgOBjnrD9vD6PtW/AgqwzCDY2I192VgKK6y95qQeAAypwe4++
aBhlzCuF83uG2B3/a7oHjJskDvXYqzdxzsWjzMsqkuPjBGocPfzyLIWBAoGAES30
u5Y52TTy6OVuo0qFU2K32ytaDvr0nvN42YNfNlOkNWI5MuDvfPGNZaEFXrPTUjsF
gv5AJprBZ0ZqPPmFk5LMwZHH4w9fECYre7WZn2fc1Ljy5zHnvsrjwYNmq+00Nasy
XRtH83pJFNTFDqq7DBY42rCN5S561fB13tA7orUCgYEA69QJnfmm6P1bC9Y6Wpb9
w1dXmCFFr/P6xs2bXKxM0Rev/fjT1QIx1Y4dDB7Z/eLzGq8YgaFRwwUJ1ca9VbD8
cMNWYPJvnV3x/BkksTM+PwscFHvTZBVf0OnVPraBMMnwGNCVeuu8wYgm0TJJYdLG
s1udzCMB6LKyPRzBQm0VRHA=
-----END PRIVATE KEY-----
"#;
}
