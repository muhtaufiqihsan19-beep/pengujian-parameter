//! Position keys: create one, and check that a public key E-Office sends back is one this
//! service issued (PKS1 signature), so nobody can slip in a key of their own.

use super::{Recipient, Service, ServiceError, backend_error};
use crate::crypto::formats::{self, PUBLIC_KEY_MAGIC};
use crate::crypto::{CryptoError, KeyIdentity, MAX_ID_LEN};

/// A new position key, as returned by `POST /keys`.
pub struct GeneratedKey {
    pub identity: KeyIdentity,
    /// PKS1: the public key with this service's signature.
    pub public_key: Vec<u8>,
    /// Stored by E-Office, needed to open DEKs (see [`crate::backends::CreatedKey`]).
    pub private_key_blob: String,
}

impl Service {
    /// Generates a key for `position_code` / `key_version` with `suite_id` (or the
    /// default suite), keeps the private half in the custody and signs the public half.
    pub async fn create_key(
        &self,
        position_code: &str,
        key_version: u32,
        suite_id: Option<&str>,
    ) -> Result<GeneratedKey, ServiceError> {
        if position_code.is_empty() || position_code.len() > MAX_ID_LEN || key_version == 0 {
            return Err(ServiceError::BadRequest(
                CryptoError::InvalidContext.to_string(),
            ));
        }
        let suite = match suite_id {
            Some(id) if !id.is_empty() => self
                .registry
                .lookup(id)
                .map_err(|e| ServiceError::BadRequest(e.to_string()))?,
            _ => self.registry.default_suite(),
        };
        let identity = KeyIdentity {
            position_code: position_code.to_string(),
            key_version,
            suite_id: suite.id().to_string(),
        };
        let internal = |e: crate::backends::BackendError| ServiceError::Internal(e.to_string());
        let created = self
            .custody
            .create(suite.as_ref(), &identity)
            .await
            .map_err(internal)?;
        let message = formats::public_key_message(
            &identity.suite_id,
            &identity.position_code,
            identity.key_version,
            &created.public_key,
        );
        let signature = self.signer.sign(&message).await.map_err(internal)?;
        Ok(GeneratedKey {
            identity,
            public_key: formats::seal_envelope(PUBLIC_KEY_MAGIC, &signature, &created.public_key),
            private_key_blob: created.private_key_blob,
        })
    }

    /// The raw public key inside a PKS1 envelope, if this service signed it for exactly
    /// this suite, position and key version.
    pub(super) async fn trusted_public_key(
        &self,
        suite_id: &str,
        position_code: &str,
        key_version: u32,
        signed_key: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let untrusted = || ServiceError::Untrusted(format!("{position_code} v{key_version}"));
        let envelope =
            formats::open_envelope(PUBLIC_KEY_MAGIC, signed_key).ok_or_else(untrusted)?;
        let message =
            formats::public_key_message(suite_id, position_code, key_version, envelope.body);
        if !self
            .signer
            .verify(&message, envelope.signature)
            .await
            .map_err(backend_error)?
        {
            return Err(untrusted());
        }
        Ok(envelope.body.to_vec())
    }

    /// [`Self::trusted_public_key`] for every recipient, in order.
    pub(super) async fn trusted_keys(
        &self,
        recipients: &[Recipient],
    ) -> Result<Vec<Vec<u8>>, ServiceError> {
        let mut keys = Vec::with_capacity(recipients.len());
        for r in recipients {
            let suite = self
                .registry
                .lookup(&r.suite_id)
                .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
            let key = self
                .trusted_public_key(suite.id(), &r.position_code, r.key_version, &r.public_key)
                .await?;
            keys.push(key);
        }
        Ok(keys)
    }
}
