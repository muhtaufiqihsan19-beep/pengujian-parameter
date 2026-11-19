//! The document's DEK: wrapped once per recipient, unwrapped for one key holder.

use zeroize::Zeroizing;

use super::{KeyHolder, Recipient, Service, ServiceError, WrappedKey, backend_error};
use crate::crypto::{Context, KeyIdentity};

impl Service {
    /// Wraps `dek` for each recipient with that recipient's suite and verified public key.
    pub(super) fn wrap_all(
        &self,
        document_id: &str,
        version: u32,
        dek: &[u8],
        recipients: &[Recipient],
        public_keys: &[Vec<u8>],
    ) -> Result<Vec<WrappedKey>, ServiceError> {
        recipients
            .iter()
            .zip(public_keys)
            .map(|(r, public_key)| {
                let suite = self
                    .registry
                    .lookup(&r.suite_id)
                    .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
                let ctx = Context {
                    document_id: document_id.to_string(),
                    version,
                    position_code: r.position_code.clone(),
                    key_version: r.key_version,
                };
                let wrapped_key = suite.wrap(public_key, dek, &ctx).map_err(|e| {
                    ServiceError::BadRequest(format!("public key of {}: {e}", r.position_code))
                })?;
                Ok(WrappedKey {
                    position_code: r.position_code.clone(),
                    key_version: r.key_version,
                    suite_id: suite.id().to_string(),
                    wrapped_key,
                })
            })
            .collect()
    }

    /// Opens the holder's wrapped DEK through the key custody.
    pub(super) async fn unwrap_dek(
        &self,
        document_id: &str,
        version: u32,
        holder: &KeyHolder,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        let suite = self
            .registry
            .lookup(&holder.suite_id)
            .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
        let identity = KeyIdentity {
            position_code: holder.position_code.clone(),
            key_version: holder.key_version,
            suite_id: suite.id().to_string(),
        };
        let ctx = Context {
            document_id: document_id.to_string(),
            version,
            position_code: holder.position_code.clone(),
            key_version: holder.key_version,
        };
        self.custody
            .unwrap_dek(
                suite.as_ref(),
                &identity,
                &holder.private_key_blob,
                &holder.wrapped_key,
                &ctx,
            )
            .await
            .map_err(backend_error)
    }
}
