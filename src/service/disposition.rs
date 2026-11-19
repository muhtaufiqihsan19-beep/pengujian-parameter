//! Disposition: a position that can open a document gives access to other positions,
//! by unwrapping the DEK with its own key and wrapping it for the targets. The content
//! is not re-encrypted.

use super::checks::{check_document, check_recipients};
use super::grant::{Action, Requested};
use super::{KeyHolder, Recipient, Service, ServiceError, WrappedKey, cpu};

impl Service {
    pub async fn rewrap(
        &self,
        document_id: &str,
        version: u32,
        source: &KeyHolder,
        targets: &[Recipient],
        grant: &str,
    ) -> Result<Vec<WrappedKey>, ServiceError> {
        check_document(document_id, version)?;
        check_recipients(targets)?;
        if targets
            .iter()
            .any(|t| t.position_code == source.position_code)
        {
            return Err(ServiceError::BadRequest("target equals source".into()));
        }
        self.authorize(
            grant,
            Requested {
                action: Action::Dispose,
                document_id,
                version,
                position_code: &source.position_code,
                key_version: source.key_version,
                targets: targets.iter().map(|t| t.position_code.as_str()).collect(),
            },
        )
        .await?;
        let public_keys = self.trusted_keys(targets).await?;
        let dek = self.unwrap_dek(document_id, version, source).await?;
        cpu(|| self.wrap_all(document_id, version, &dek, targets, &public_keys))
    }
}
