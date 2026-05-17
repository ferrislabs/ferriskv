use std::sync::Arc;

use bytes::Bytes;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("key not found: {0:?}")]
    NotFound(Bytes),

    #[error("storage: {0}")]
    Storage(#[from] fjall::Error),

    #[error("not leader, redirect to {leader}")]
    NotLeader { leader: Arc<str> },

    #[error("tenant not found: {0}")]
    UnknownTenant(Arc<str>),

    #[error("shard {0} not owned by this node")]
    NotOwner(u16),

    #[error("corrupted data: {0}")]
    Corrupt(&'static str),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration: {0}")]
    Config(String),
}
