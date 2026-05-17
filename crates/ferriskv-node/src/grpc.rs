#![allow(clippy::result_large_err)]

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use ferriskv_core::{Error, KeyCodec, Storage, Subspace};
use ferriskv_proto::ferris_kv_server::FerrisKv;
use ferriskv_proto::{
    BatchRequest, BatchResponse, DeleteRequest, DeleteResponse, GetRequest, GetResponse, KeyValue,
    PutRequest, PutResponse, ScanChunk, ScanRequest, WatchEvent, WatchRequest,
};
use futures::stream::Iter;
use tonic::{Request, Response, Status};

use crate::auth_layer::Principal;
use crate::service::NodeService;

const PERM_READ: &str = "read";
const PERM_WRITE: &str = "write";
const PERM_DELETE: &str = "delete";
const PERM_WATCH: &str = "watch";

const OP_PUT: u32 = 1;
const OP_DELETE: u32 = 2;

const SCAN_CHUNK_SIZE: usize = 256;

pub struct GrpcApi {
    inner: Arc<NodeService>,
}

impl GrpcApi {
    pub fn new(inner: Arc<NodeService>) -> Self {
        Self { inner }
    }

    #[inline]
    fn enforce_key_size(&self, key: &[u8]) -> Result<(), Status> {
        let max = self.inner.config.limits.max_key_size;
        if key.len() > max {
            return Err(Status::invalid_argument(format!(
                "key size {} exceeds limit {}",
                key.len(),
                max
            )));
        }
        Ok(())
    }

    #[inline]
    fn enforce_value_size(&self, value: &[u8]) -> Result<(), Status> {
        let max = self.inner.config.limits.max_value_size;
        if value.len() > max {
            return Err(Status::resource_exhausted(format!(
                "value size {} exceeds limit {}",
                value.len(),
                max
            )));
        }
        Ok(())
    }

    #[inline]
    fn enforce_batch_size(&self, n: usize) -> Result<(), Status> {
        let max = self.inner.config.limits.max_batch_ops;
        if n > max {
            return Err(Status::invalid_argument(format!(
                "batch size {n} exceeds limit {max}"
            )));
        }
        Ok(())
    }

    #[inline]
    fn cap_scan_limit(&self, requested: u32) -> u32 {
        let max = self.inner.config.limits.max_scan_limit;
        if requested == 0 || requested > max {
            max
        } else {
            requested
        }
    }
}

#[inline]
fn to_status(e: Error) -> Status {
    match e {
        Error::NotFound(_) => Status::not_found(e.to_string()),
        Error::NotLeader { .. } => Status::failed_precondition(e.to_string()),
        Error::UnknownTenant(_) => Status::unauthenticated(e.to_string()),
        Error::NotOwner(_) => Status::failed_precondition(e.to_string()),
        Error::Corrupt(_) | Error::Storage(_) | Error::Io(_) | Error::Config(_) => {
            Status::internal(e.to_string())
        }
    }
}

#[inline]
fn check_tenant(t: &str) -> Result<(), Status> {
    if t.is_empty() {
        return Err(Status::invalid_argument("tenant must not be empty"));
    }
    if t.len() > 255 {
        return Err(Status::invalid_argument("tenant exceeds 255 bytes"));
    }
    Ok(())
}

fn authorize<T>(req: &Request<T>, tenant: &str, perm: &str) -> Result<(), Status> {
    let principal = req
        .extensions()
        .get::<Principal>()
        .ok_or_else(|| Status::internal("auth layer missing"))?;

    if let Some(claim_tenant) = principal.tenant() {
        if claim_tenant != tenant {
            return Err(Status::permission_denied(format!(
                "tenant {tenant} not authorized for this principal"
            )));
        }
    }

    if !principal.allows(perm) {
        return Err(Status::permission_denied(format!(
            "permission {perm} required"
        )));
    }
    Ok(())
}

#[inline]
fn encode_data_key(tenant: &str, payload: &[u8]) -> Result<Bytes, Status> {
    KeyCodec::encode(tenant, Subspace::Data, payload).map_err(to_status)
}

struct ScanBounds {
    start: Bytes,
    end: Bytes,
    strip_len: usize,
}

fn encode_data_scan_bounds(tenant: &str, user_prefix: &[u8]) -> Result<ScanBounds, Status> {
    let sub_prefix = KeyCodec::encode_subspace_prefix(tenant, Subspace::Data).map_err(to_status)?;
    let strip_len = sub_prefix.len();
    let mut start = BytesMut::with_capacity(sub_prefix.len() + user_prefix.len());
    start.put_slice(&sub_prefix);
    start.put_slice(user_prefix);
    let end = next_prefix_bound(&start);
    Ok(ScanBounds {
        start: start.freeze(),
        end,
        strip_len,
    })
}

fn next_prefix_bound(prefix: &[u8]) -> Bytes {
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last == 0xFF {
            end.pop();
        } else {
            *end.last_mut().expect("non-empty") = last + 1;
            return Bytes::from(end);
        }
    }
    Bytes::new()
}

#[tonic::async_trait]
impl FerrisKv for GrpcApi {
    async fn get(&self, req: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_READ)?;
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        let k = encode_data_key(&r.tenant, &r.key)?;
        let value = self.inner.get(&k).map_err(to_status)?;
        Ok(Response::new(match value {
            Some(v) => GetResponse {
                found: true,
                value: v,
                version: 0,
            },
            None => GetResponse {
                found: false,
                value: Default::default(),
                version: 0,
            },
        }))
    }

    async fn put(&self, req: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_WRITE)?;
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        self.enforce_value_size(&r.value)?;
        let k = encode_data_key(&r.tenant, &r.key)?;
        self.inner.put(&k, r.value).map_err(to_status)?;
        Ok(Response::new(PutResponse { version: 0 }))
    }

    async fn delete(
        &self,
        req: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_DELETE)?;
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        let k = encode_data_key(&r.tenant, &r.key)?;
        let found = self.inner.get(&k).map_err(to_status)?.is_some();
        self.inner.delete(&k).map_err(to_status)?;
        Ok(Response::new(DeleteResponse { found }))
    }

    type ScanStream = Iter<std::vec::IntoIter<Result<ScanChunk, Status>>>;

    async fn scan(&self, req: Request<ScanRequest>) -> Result<Response<Self::ScanStream>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_READ)?;
        let r = req.into_inner();
        let bounds = encode_data_scan_bounds(&r.tenant, &r.prefix)?;

        let iter = self
            .inner
            .scan_range(&bounds.start, &bounds.end)
            .map_err(to_status)?;

        let limit = self.cap_scan_limit(r.limit) as usize;

        let mut chunks: Vec<Result<ScanChunk, Status>> = Vec::new();
        let mut current: Vec<KeyValue> = Vec::with_capacity(SCAN_CHUNK_SIZE);
        for (k, v) in iter.take(limit) {
            let user_key = k.slice(bounds.strip_len..);
            current.push(KeyValue {
                key: user_key,
                value: v,
            });
            if current.len() >= SCAN_CHUNK_SIZE {
                chunks.push(Ok(ScanChunk {
                    entries: std::mem::take(&mut current),
                }));
            }
        }
        if !current.is_empty() {
            chunks.push(Ok(ScanChunk { entries: current }));
        }
        Ok(Response::new(futures::stream::iter(chunks)))
    }

    type WatchStream = Iter<std::vec::IntoIter<Result<WatchEvent, Status>>>;

    async fn watch(
        &self,
        req: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_WATCH)?;
        Err(Status::unimplemented("watch not implemented yet"))
    }

    async fn batch(&self, req: Request<BatchRequest>) -> Result<Response<BatchResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        let needs_write = req.get_ref().ops.iter().any(|o| o.op == OP_PUT);
        let needs_delete = req.get_ref().ops.iter().any(|o| o.op == OP_DELETE);
        let tenant = req.get_ref().tenant.clone();
        if needs_write {
            authorize(&req, &tenant, PERM_WRITE)?;
        }
        if needs_delete {
            authorize(&req, &tenant, PERM_DELETE)?;
        }
        let r = req.into_inner();
        self.enforce_batch_size(r.ops.len())?;
        for op in r.ops {
            self.enforce_key_size(&op.key)?;
            if op.op == OP_PUT {
                self.enforce_value_size(&op.value)?;
            }
            let k = encode_data_key(&r.tenant, &op.key)?;
            match op.op {
                OP_PUT => self.inner.put(&k, op.value).map_err(to_status)?,
                OP_DELETE => self.inner.delete(&k).map_err(to_status)?,
                other => return Err(Status::invalid_argument(format!("unknown op code {other}"))),
            }
        }
        Ok(Response::new(BatchResponse { ok: true }))
    }
}
