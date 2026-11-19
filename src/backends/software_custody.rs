//! Key custody in software: key pairs are generated in this process with `aws-lc-rs`, and
//! each private key leaves only as a JKB1 envelope sealed by a [`Sealer`] (OpenBao Transit
//! in production). E-Office stores that sealed blob; this service unseals it for the
//! moment it needs to open a DEK, then drops it (zeroized).

use std::sync::Arc;

use zeroize::Zeroizing;

use super::{BackendError, BoxFuture, CreatedKey, KeyCustody, Sealer};
use crate::crypto::formats::{decode_jkb1, encode_jkb1};
use crate::crypto::{Context, KeyIdentity, Suite};

pub struct SoftwareKeyCustody {
    sealer: Arc<dyn Sealer>,
}

impl SoftwareKeyCustody {
    pub fn new(sealer: Arc<dyn Sealer>) -> Self {
        Self { sealer }
    }

    async fn open_private(
        &self,
        id: &KeyIdentity,
        blob: &str,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let envelope = self.sealer.unseal(blob).await?;
        let (got, private_key) = decode_jkb1(&envelope).ok_or(BackendError::Mismatch)?;
        if &got != id {
            return Err(BackendError::Mismatch);
        }
        Ok(private_key)
    }
}

impl KeyCustody for SoftwareKeyCustody {
    fn create<'a>(
        &'a self,
        suite: &'a dyn Suite,
        id: &'a KeyIdentity,
    ) -> BoxFuture<'a, Result<CreatedKey, BackendError>> {
        Box::pin(async move {
            let pair = suite.generate_key_pair()?;
            let envelope = encode_jkb1(id, &pair.private_key);
            let private_key_blob = self.sealer.seal(&envelope).await?;
            Ok(CreatedKey {
                public_key: pair.public_key,
                private_key_blob,
            })
        })
    }

    fn unwrap_dek<'a>(
        &'a self,
        suite: &'a dyn Suite,
        id: &'a KeyIdentity,
        private_key_blob: &'a str,
        wrapped: &'a [u8],
        ctx: &'a Context,
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BackendError>> {
        Box::pin(async move {
            let private_key = self.open_private(id, private_key_blob).await?;
            Ok(suite.unwrap(&private_key, wrapped, ctx)?)
        })
    }

    fn ready(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            match self.sealer.seal(b"readyz").await {
                Ok(blob) => self
                    .sealer
                    .unseal(&blob)
                    .await
                    .is_ok_and(|p| &p[..] == b"readyz"),
                Err(_) => false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::InsecureDevSealer;
    use crate::crypto::CompositeV2;
    use crate::crypto::primitives::random;

    fn custody() -> SoftwareKeyCustody {
        SoftwareKeyCustody::new(Arc::new(InsecureDevSealer::new().unwrap()))
    }

    fn id(position_code: &str, suite: &dyn Suite) -> KeyIdentity {
        KeyIdentity {
            position_code: position_code.into(),
            key_version: 1,
            suite_id: suite.id().into(),
        }
    }

    fn ctx(id: &KeyIdentity) -> Context {
        Context {
            document_id: "DOC-1".into(),
            version: 1,
            position_code: id.position_code.clone(),
            key_version: id.key_version,
        }
    }

    #[tokio::test]
    async fn create_and_unwrap() {
        let c = custody();
        {
            let suite: &dyn Suite = &CompositeV2;
            let id = id("HEAD-OF-BUREAU", suite);
            let key = c.create(suite, &id).await.unwrap();
            let dek = random::dek().unwrap();
            let wrapped = suite.wrap(&key.public_key, &dek[..], &ctx(&id)).unwrap();
            let got = c
                .unwrap_dek(suite, &id, &key.private_key_blob, &wrapped, &ctx(&id))
                .await
                .unwrap();
            assert_eq!(&got[..], &dek[..], "{}", suite.id());
        }
    }

    #[tokio::test]
    async fn swapped_blob_detected() {
        let c = custody();
        let suite = &CompositeV2;
        let a = id("HEAD-OF-BUREAU", suite);
        let b = id("ADMIN-STAFF", suite);
        let key_a = c.create(suite, &a).await.unwrap();
        let key_b = c.create(suite, &b).await.unwrap();
        let wrapped = suite
            .wrap(&key_a.public_key, &random::dek().unwrap()[..], &ctx(&a))
            .unwrap();
        assert!(matches!(
            c.unwrap_dek(suite, &a, &key_b.private_key_blob, &wrapped, &ctx(&a))
                .await,
            Err(BackendError::Mismatch)
        ));
        let mut wrong_version = a.clone();
        wrong_version.key_version = 2;
        assert!(matches!(
            c.unwrap_dek(
                suite,
                &wrong_version,
                &key_a.private_key_blob,
                &wrapped,
                &ctx(&a)
            )
            .await,
            Err(BackendError::Mismatch)
        ));
    }

    #[tokio::test]
    async fn blob_from_another_sealer_rejected() {
        let suite = &CompositeV2;
        let a = id("HEAD-OF-BUREAU", suite);
        let key = custody().create(suite, &a).await.unwrap();
        let wrapped = suite
            .wrap(&key.public_key, &random::dek().unwrap()[..], &ctx(&a))
            .unwrap();
        assert!(matches!(
            custody()
                .unwrap_dek(suite, &a, &key.private_key_blob, &wrapped, &ctx(&a))
                .await,
            Err(BackendError::BadBlob)
        ));
    }

    #[tokio::test]
    async fn ready_round_trips() {
        assert!(custody().ready().await);
    }
}
