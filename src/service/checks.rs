//! Checks that run before any key is touched: input limits, then the grant.

use std::collections::HashSet;

use super::grant::{GrantError, Requested, now_unix};
use super::{Recipient, Service, ServiceError};
use crate::crypto::MAX_ID_LEN;

pub const MAX_RECIPIENTS: usize = 1024;

pub(super) fn check_document(document_id: &str, version: u32) -> Result<(), ServiceError> {
    if document_id.is_empty() || document_id.len() > MAX_ID_LEN || version == 0 {
        return Err(ServiceError::BadRequest(format!(
            "document_id (1..{MAX_ID_LEN} bytes) and version (> 0) are required"
        )));
    }
    Ok(())
}

pub(super) fn check_recipients(recipients: &[Recipient]) -> Result<(), ServiceError> {
    if recipients.is_empty() {
        return Err(ServiceError::BadRequest("no recipients".into()));
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(ServiceError::BadRequest(format!(
            "more than {MAX_RECIPIENTS} recipients"
        )));
    }
    let mut seen = HashSet::with_capacity(recipients.len());
    for r in recipients {
        if !seen.insert(r.position_code.as_str()) {
            return Err(ServiceError::BadRequest(format!(
                "duplicate position {}",
                r.position_code
            )));
        }
    }
    Ok(())
}

impl Service {
    /// Verifies the grant for `want` and writes the `security_audit` log line.
    pub(super) async fn authorize(
        &self,
        grant: &str,
        want: Requested<'_>,
    ) -> Result<(), ServiceError> {
        let claims = self
            .grants
            .verify_with_source(grant, &want, now_unix())
            .await
            .map_err(|e| match e {
                GrantError::KeysUnavailable(e) => ServiceError::Internal(e),
                e => ServiceError::Forbidden(e.to_string()),
            })?;
        tracing::info!(
            security_audit = true,
            sub = %claims.sub,
            action = ?claims.action,
            document_id = %claims.document_id,
            version = claims.version,
            position_code = %claims.position_code,
            targets = ?claims.targets,
            "access granted"
        );
        Ok(())
    }
}
