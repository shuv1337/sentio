use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use sentio_core::tenant::TenantId;
use sentio_core::traits::{ApiKeyRepository, OAuthTokenRepository};
use sentio_store::postgres::{PgApiKeyRepository, PgOAuthTokenRepository};

use crate::errors::ApiError;
use crate::state::AppState;

// ──────────────────────────────────────────────────────────────────────────────
// Auth context - extracted from Authorization: Bearer <token>
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: TenantId,
    pub scopes: Vec<String>,
    /// Set when the bearer matches `SENTIO_INGEST_TOKEN`. That token is
    /// ingest-only (`messages:ingest`) and is not an API key, so recipient
    /// domains are resolved globally the same way SMTP inbound does.
    pub shared_ingest: bool,
}

impl AuthContext {
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == scope || s == "*") {
            Ok(())
        } else {
            Err(ApiError::Auth(format!("missing required scope: {scope}")))
        }
    }
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // When the auth middleware has already resolved the context, reuse
        // it instead of repeating the database lookup.
        // When the auth middleware has already resolved the context, reuse
        // it instead of repeating the database lookup.
        let cached = parts.extensions.get::<AuthContext>().cloned();

        let pool = state.pool.clone();
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        async move {
            if let Some(ctx) = cached {
                return Ok(ctx);
            }
            let auth_header =
                auth_header.ok_or_else(|| ApiError::Auth("missing authorization header".into()))?;

            let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
                ApiError::Auth("invalid authorization format, expected Bearer token".into())
            })?;

            if presented_bearer_is_ingest_token(token) {
                return Ok(AuthContext {
                    tenant_id: TenantId(uuid::Uuid::nil()),
                    scopes: vec!["messages:ingest".into()],
                    shared_ingest: true,
                });
            }

            // SHA-256 hash the token for lookup
            let key_hash = {
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                hex::encode(hasher.finalize())
            };

            // Try API key first. A miss is signalled by SentioError::Auth;
            // any other error is an infrastructure failure and must not be
            // reported to the caller as a bad token.
            let api_key_repo = PgApiKeyRepository::new(pool.clone());
            match api_key_repo.verify(&key_hash).await {
                Ok(record) => {
                    return Ok(AuthContext {
                        tenant_id: record.tenant_id,
                        scopes: record.scopes,
                        shared_ingest: false,
                    });
                }
                Err(sentio_core::error::SentioError::Auth(_)) => {}
                Err(e) => {
                    tracing::error!("api key lookup failed: {e}");
                    return Err(ApiError::Internal(
                        "authentication backend unavailable".into(),
                    ));
                }
            }

            // Fall back to OAuth bearer token
            let oauth_repo = PgOAuthTokenRepository::new(pool);
            match oauth_repo.get_by_hash(&key_hash).await {
                Ok(record) => {
                    if record.revoked_at.is_some() {
                        return Err(ApiError::Auth("token has been revoked".into()));
                    }
                    if record.expires_at < chrono::Utc::now() {
                        return Err(ApiError::Auth("token has expired".into()));
                    }
                    Ok(AuthContext {
                        tenant_id: record.tenant_id,
                        scopes: record.scopes,
                        shared_ingest: false,
                    })
                }
                // A token that matches no row is a client error, not an
                // outage. The two repositories disagree on how they say
                // "no such row": PgApiKeyRepository::verify returns Auth,
                // PgOAuthTokenRepository::get_by_hash returns NotFound.
                // Both mean the same thing here.
                Err(
                    sentio_core::error::SentioError::Auth(_)
                    | sentio_core::error::SentioError::NotFound { .. },
                ) => Err(ApiError::Auth("invalid or expired token".into())),
                Err(e) => {
                    tracing::error!("oauth token lookup failed: {e}");
                    Err(ApiError::Internal(
                        "authentication backend unavailable".into(),
                    ))
                }
            }
        }
    }
}

/// Env var whose value is accepted as a Bearer token on ingest.
/// Distinct from API keys: it grants only `messages:ingest`.
pub const INGEST_TOKEN_ENV: &str = "SENTIO_INGEST_TOKEN";

fn presented_bearer_is_ingest_token(token: &str) -> bool {
    token_equals_configured(token, std::env::var(INGEST_TOKEN_ENV).ok().as_deref())
}

fn token_equals_configured(presented: &str, configured: Option<&str>) -> bool {
    match configured {
        Some(expected) if !expected.is_empty() => {
            constant_time_eq(presented.as_bytes(), expected.as_bytes())
        }
        _ => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ──────────────────────────────────────────────────────────────────────────────
// Auth middleware
// ──────────────────────────────────────────────────────────────────────────────

/// Resolve the bearer token once per request and publish the resulting
/// `AuthContext` as a request extension, so downstream middleware (per-tenant
/// rate limiting) and handlers share a single database lookup.
///
/// Applied only to authenticated route groups - public endpoints such as
/// `/health`, `/docs`, and `/track` are mounted outside this layer.
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let ctx = AuthContext::from_request_parts(&mut parts, &state).await?;
    parts.extensions.insert(ctx);
    let req = axum::http::Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

// ──────────────────────────────────────────────────────────────────────────────
// Bootstrap credential check
// ──────────────────────────────────────────────────────────────────────────────

/// Warn loudly if the well-known bootstrap admin API key is still active.
///
/// `migrations/002_bootstrap.sql` seeds an admin tenant with a publicly-known
/// key (`sentio_bootstrap_admin_CHANGE_ME`) so a fresh install is usable. The
/// README instructs operators to rotate it; this check makes a forgotten
/// rotation impossible to miss at startup.
pub async fn warn_if_bootstrap_key_active(pool: &sqlx::PgPool) {
    const BOOTSTRAP_KEY: &str = "sentio_bootstrap_admin_CHANGE_ME";

    let key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(BOOTSTRAP_KEY.as_bytes());
        hex::encode(hasher.finalize())
    };

    let api_key_repo = PgApiKeyRepository::new(pool.clone());
    match api_key_repo.verify(&key_hash).await {
        Ok(record) => {
            tracing::warn!(
                key_prefix = %record.key_prefix,
                "the bootstrap admin API key shipped in migrations/002_bootstrap.sql \
                 is still active and publicly known - rotate it now via \
                 POST /v1/tenants/{}/api-keys, then delete the bootstrap key",
                record.tenant_id
            );
        }
        Err(sentio_core::error::SentioError::Auth(_)) => {}
        Err(e) => {
            tracing::debug!(error = %e, "could not check bootstrap key status");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_token_unset_or_empty_never_matches() {
        assert!(!token_equals_configured("anything", None));
        assert!(!token_equals_configured("anything", Some("")));
    }

    #[test]
    fn ingest_token_matches_only_exact_configured_value() {
        const TOKEN: &str = "ingest-test-token";
        assert!(token_equals_configured(TOKEN, Some(TOKEN)));
        assert!(!token_equals_configured(TOKEN, Some("other-token")));
        assert!(!token_equals_configured("ingest-test-toke", Some(TOKEN)));
    }
}
