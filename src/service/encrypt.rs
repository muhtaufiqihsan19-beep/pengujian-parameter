//! Encrypt a document version (or a text) for its recipients.
//!
//! 1. Check input, then check every recipient's public key is one this service issued.
//! 2. Generate a fresh DEK, wrap it for each recipient, encrypt the content as EKS1.
//! 3. Sign the EKS1 ciphertext (CTS1) so a forged or swapped ciphertext is refused later.

use super::checks::{check_document, check_recipients};
use super::{Encrypted, Recipient, Service, ServiceError, cpu};
use crate::crypto::eks1;
use crate::crypto::formats::{self, CIPHERTEXT_MAGIC};
use crate::crypto::primitives::random;

impl Service {
    pub async fn encrypt(
        &self,
        document_id: &str,
        version: u32,
        plaintext: &[u8],
        recipients: &[Recipient],
    ) -> Result<Encrypted, ServiceError> {
        check_document(document_id, version)?;
        if plaintext.len() > self.max_plaintext {
            return Err(ServiceError::TooLarge);
        }
        check_recipients(recipients)?;
        let public_keys = self.trusted_keys(recipients).await?;

        let (wrapped_keys, content, message) = cpu(|| {
            let dek = random::dek().map_err(|_| ServiceError::Internal("RNG".into()))?;
            let wrapped =
                self.wrap_all(document_id, version, &dek[..], recipients, &public_keys)?;
            let content =
                eks1::encrypt_to_vec(plaintext, &dek[..], document_id, version, self.chunk_size)
                    .map_err(|e| match e {
                        eks1::Eks1Error::Format => ServiceError::BadRequest(e.to_string()),
                        other => ServiceError::Internal(other.to_string()),
                    })?;
            let message = formats::ciphertext_message(document_id, version, &content);
            Ok::<_, ServiceError>((wrapped, content, message))
        })?;
        let signature = self
            .signer
            .sign(&message)
            .await
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        let mut ciphertext = formats::envelope_prefix(CIPHERTEXT_MAGIC, &signature);
        ciphertext.reserve_exact(content.len());
        ciphertext.extend_from_slice(&content);
        Ok(Encrypted {
            ciphertext,
            wrapped_keys,
        })
    }
}
