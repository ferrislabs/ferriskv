use std::sync::Arc;

use bytes::Bytes;

pub type Key = Bytes;
pub type Value = Bytes;
pub type ShardId = u64;

pub type TenantId = Arc<str>;
pub type NodeId = Arc<str>;
