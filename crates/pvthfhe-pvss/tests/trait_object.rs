//! Trait-object safety smoke test for the frozen PVSS adapter API.

use pvthfhe_pvss::PvssAdapter;
use pvthfhe_types::{ProtocolBytes, ShareSecret};

struct NoopPvssAdapter;

impl PvssAdapter for NoopPvssAdapter {
    fn deal(
        &self,
        _secret: &[u8],
        _recipient_pks: &[Vec<u8>],
        _ctx: &pvthfhe_pvss::PvssContext,
    ) -> Result<pvthfhe_pvss::EncryptedShares, pvthfhe_pvss::PvssError> {
        Err(pvthfhe_pvss::PvssError::BackendError("noop-pvss".into()))
    }

    fn verify_shares(
        &self,
        _shares: &pvthfhe_pvss::EncryptedShares,
        _ctx: &pvthfhe_pvss::PvssContext,
    ) -> Result<(), pvthfhe_pvss::PvssError> {
        Err(pvthfhe_pvss::PvssError::BackendError("noop-pvss".into()))
    }

    fn recover(
        &self,
        _decrypted_shares: &[pvthfhe_pvss::DecryptedShare],
        _ctx: &pvthfhe_pvss::PvssContext,
    ) -> Result<Vec<u8>, pvthfhe_pvss::PvssError> {
        Err(pvthfhe_pvss::PvssError::BackendError("noop-pvss".into()))
    }

    fn backend_id(&self) -> &'static str {
        "noop-pvss"
    }
}

#[test]
fn pvss_adapter_is_trait_object_safe() {
    let adapter: Box<dyn PvssAdapter> = Box::new(NoopPvssAdapter);
    let ctx = pvthfhe_pvss::PvssContext {
        n: 3,
        t: 2,
        session_id: b"session".to_vec(),
        epoch: 0,
        dkg_root: vec![],
        dealer_index: 1,
    };
    let shares = pvthfhe_pvss::EncryptedShares {
        ciphertexts: vec![vec![1, 2, 3]],
        share_bytes: vec![vec![7, 8]],
        proofs: vec![vec![4, 5, 6]],
        parity_proof: None,
        backend_id: adapter.backend_id().to_owned(),
    };
    let decrypted_shares = vec![pvthfhe_pvss::DecryptedShare {
        index: 0,
        share_bytes: ShareSecret::new(vec![7, 8]),
        proof: ProtocolBytes(vec![9]),
    }];

    assert!(!adapter.backend_id().is_empty());
    assert!(matches!(
        adapter.deal(b"secret", &[vec![0xAA]], &ctx),
        Err(pvthfhe_pvss::PvssError::BackendError(_))
    ));
    assert!(matches!(
        adapter.verify_shares(&shares, &ctx),
        Err(pvthfhe_pvss::PvssError::BackendError(_))
    ));
    assert!(matches!(
        adapter.recover(&decrypted_shares, &ctx),
        Err(pvthfhe_pvss::PvssError::BackendError(_))
    ));
}
