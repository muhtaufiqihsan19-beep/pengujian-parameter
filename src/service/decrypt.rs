//! Decrypt a document version (or a text) with one holder's key.
//!
//! Order matters: cheap checks and the grant first, then the CTS1 signature and the EKS1
//! header, and only then the key custody (which may call OpenBao or an HSM).

use zeroize::Zeroizing;

use super::checks::check_document;
use super::grant::{Action, Requested};
use super::{KeyHolder, Service, ServiceError, cpu};
use crate::crypto::eks1;
use crate::crypto::formats::{self, CIPHERTEXT_MAGIC};

impl Service {
    pub async fn decrypt(
        &self,
        document_id: &str,
        version: u32,
        holder: &KeyHolder,
        ciphertext: Vec<u8>,
        grant: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        check_document(document_id, version)?;
        self.authorize(
            grant,
            Requested {
                action: Action::Decrypt,
                document_id,
                version,
                position_code: &holder.position_code,
                key_version: holder.key_version,
                targets: Vec::new(),
            },
        )
        .await?;
        let envelope =
            formats::open_envelope(CIPHERTEXT_MAGIC, &ciphertext).ok_or(ServiceError::Open)?;
        let (signature, offset) = (envelope.signature.to_string(), envelope.body_offset);
        let content = envelope.body;
        let (header, raw) = eks1::read_header(&mut &content[..]).map_err(|_| ServiceError::Open)?;
        if header.document_id != document_id || header.version != version {
            return Err(ServiceError::Open);
        }
        if header.plaintext_len(content.len() - raw.len()) > self.max_plaintext {
            return Err(ServiceError::TooLarge);
        }
        let message = cpu(|| formats::ciphertext_message(document_id, version, content));
        let authentic = self
            .signer
            .verify(&message, &signature)
            .await
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        if !authentic {
            return Err(ServiceError::Open);
        }

        let dek = self.unwrap_dek(document_id, version, holder).await?;
        let mut buf = Zeroizing::new(ciphertext);
        buf.drain(..offset);
        cpu(|| eks1::decrypt_in_place(&mut buf, &dek)).map_err(|_| ServiceError::Open)?;
        Ok(buf)
    }

    /// [`Self::decrypt`] for content that must be UTF-8 text.
    pub async fn decrypt_text(
        &self,
        document_id: &str,
        version: u32,
        holder: &KeyHolder,
        ciphertext: Vec<u8>,
        grant: &str,
    ) -> Result<Zeroizing<String>, ServiceError> {
        let mut plain = self
            .decrypt(document_id, version, holder, ciphertext, grant)
            .await?;
        match String::from_utf8(std::mem::take(&mut *plain)) {
            Ok(text) => Ok(Zeroizing::new(text)),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
                Err(ServiceError::BadRequest("content is not UTF-8 text".into()))
            }
        }
    }
}
