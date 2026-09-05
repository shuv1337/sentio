use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use sqlx::PgPool;

use sentio_core::config::SentioConfig;
use sentio_queue::Publisher;
use sentio_smtp_server::MessageProcessor;
use sentio_storage::S3BlobStore;
use sentio_store::RedisPool;

// ──────────────────────────────────────────────────────────────────────────────
// Application state
// ──────────────────────────────────────────────────────────────────────────────

pub type KeyedRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub publisher: Arc<Publisher>,
    pub blob_store: Arc<S3BlobStore>,
    pub config: Arc<SentioConfig>,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    /// Pre-auth limiter keyed by client IP; guards token brute force and
    /// unauthenticated endpoints.
    pub ip_rate_limiter: Arc<KeyedRateLimiter>,
    pub kv: Option<RedisPool>,
    /// Same callback SMTP DATA completion uses (`InboundPipeline::process`).
    /// `None` when the API process is running without the inbound pipeline
    /// (tests, `openapi` export).
    pub inbound_processor: Option<MessageProcessor>,
}

/// Requests allowed per client IP per minute before authentication.
const IP_LIMIT_PER_MINUTE: u32 = 120;

impl AppState {
    pub fn new(
        pool: PgPool,
        publisher: Publisher,
        blob_store: S3BlobStore,
        config: SentioConfig,
    ) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(600).unwrap());
        let rate_limiter = RateLimiter::dashmap(quota);
        let ip_quota = Quota::per_minute(NonZeroU32::new(IP_LIMIT_PER_MINUTE).unwrap());
        let ip_rate_limiter = RateLimiter::dashmap(ip_quota);

        Self {
            pool,
            publisher: Arc::new(publisher),
            blob_store: Arc::new(blob_store),
            config: Arc::new(config),
            rate_limiter: Arc::new(rate_limiter),
            ip_rate_limiter: Arc::new(ip_rate_limiter),
            kv: None,
            inbound_processor: None,
        }
    }

    pub fn with_kv(mut self, kv: RedisPool) -> Self {
        self.kv = Some(kv);
        self
    }

    pub fn with_inbound_processor(mut self, processor: MessageProcessor) -> Self {
        self.inbound_processor = Some(processor);
        self
    }
}
