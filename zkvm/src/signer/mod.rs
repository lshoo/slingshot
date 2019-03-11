#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

// Modules for signing protocol

pub mod prover;

#[derive(Clone)]
pub struct PrivKey(Scalar);

#[derive(Clone)]
pub struct PubKey(RistrettoPoint);

pub struct MultiKey(Vec<PubKey>); // TODO: also include Option<Scalar> for signing key?

#[derive(Clone)]
pub struct PubKeyHash(Scalar);

#[derive(Debug, Clone)]
pub struct Signature {
    s: Scalar,
    R: RistrettoPoint,
}

#[derive(Clone)]
pub struct Shared {
    X_agg: PubKey,
    L: PubKeyHash,
}

impl MultiKey {
    pub fn aggregate(&self) -> (PubKey, PubKeyHash) {
        let L = self.L();

        // INTERVIEW PART 1: create Pubkey(X) correctly.
        let mut X = RistrettoPoint::default();
        for X_i in &self.0 {
            let a_i = H_agg(L, X_i.0);
            X = X + a_i * X_i.0;
        }

        (PubKey(X), PubKeyHash(L))
    }

    fn L(&self) -> Scalar {
        let mut transcript = Transcript::new(b"key aggregation");
        for X_i in &self.0 {
            transcript.commit_point(b"X_i.L", &X_i.0.compress());
        }
        transcript.challenge_scalar(b"L")
    }
}

impl Signature {
    pub fn verify(&self, m: Vec<u8>, X_agg: PubKey) -> bool {
        // Make c = H(X_agg, R, m)
        let c = H_sig(X_agg.0, self.R, m);

        // INTERVIEW PART 4: perform verification check
        self.s * RISTRETTO_BASEPOINT_POINT == self.R + c * X_agg.0
        // false
    }
}

pub fn H_agg(L_hash: Scalar, X_i: RistrettoPoint) -> Scalar {
    let mut transcript = Transcript::new(b"H_agg");
    transcript.commit_scalar(b"L", &L_hash);
    transcript.commit_point(b"X_i", &X_i.compress());
    transcript.challenge_scalar(b"a_i")
}

pub fn H_sig(X_agg: RistrettoPoint, R: RistrettoPoint, m: Vec<u8>) -> Scalar {
    let mut transcript = Transcript::new(b"H_sig");
    transcript.commit_point(b"X_agg", &X_agg.compress());
    transcript.commit_point(b"R", &R.compress());
    transcript.commit_bytes(b"m", &m);
    transcript.challenge_scalar(b"c")
}

pub fn H_nonce(R: RistrettoPoint) -> Scalar {
    let mut transcript = Transcript::new(b"nonce precommitment");
    transcript.commit_point(b"R_i", &R.compress());
    transcript.challenge_scalar(b"nonce.precommit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::prover::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn make_aggregated_pubkey() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (pub_key, pub_key_hash) = agg_pubkey_helper(&priv_keys);

        let expected_pub_key = CompressedRistretto::from_slice(&[
            196, 129, 92, 103, 69, 90, 78, 220, 115, 228, 144, 155, 49, 101, 113, 9, 31, 25, 176,
            250, 249, 62, 207, 216, 120, 149, 199, 26, 101, 118, 69, 3,
        ]);
        let expected_pub_key_hash = Scalar::from_bits([
            229, 114, 44, 119, 192, 112, 253, 230, 246, 19, 57, 241, 95, 48, 219, 162, 72, 240,
            243, 154, 205, 94, 152, 30, 58, 129, 49, 209, 141, 80, 74, 0,
        ]);

        assert_eq!(expected_pub_key, pub_key.0.compress());
        assert_eq!(expected_pub_key_hash, pub_key_hash.0);
    }

    fn agg_pubkey_helper(priv_keys: &Vec<PrivKey>) -> (PubKey, PubKeyHash) {
        let G = RISTRETTO_BASEPOINT_POINT;
        let multi_key = MultiKey(
            priv_keys
                .iter()
                .map(|priv_key| PubKey(G * priv_key.0))
                .collect(),
        );
        multi_key.aggregate()
    }

    #[test]
    fn sign_message() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (X_agg, L) = agg_pubkey_helper(&priv_keys);

        sign_helper(priv_keys, X_agg, L);
    }

    fn sign_helper(priv_keys: Vec<PrivKey>, X_agg: PubKey, L: PubKeyHash) -> Signature {
        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .map(|x_i| PartyAwaitingPrecommitments::new(x_i, X_agg.clone(), L.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone(), b"message to sign".to_vec()))
            .unzip();

        let pub_keys: Vec<_> = priv_keys
            .iter()
            .map(|priv_key| PubKey(priv_key.0 * RISTRETTO_BASEPOINT_POINT))
            .collect();
        let signatures: Vec<_> = parties
            .into_iter()
            .map(|p| p.receive_and_verify_siglets(siglets.clone(), pub_keys.clone()))
            .collect();

        // Check that signatures from all parties are the same
        let cmp = &signatures[0];
        for sig in &signatures {
            assert_eq!(cmp.s, sig.s);
            assert_eq!(cmp.R, sig.R)
        }

        (signatures[0].clone())
    }

    #[test]
    fn verify_sig() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (X_agg, L) = agg_pubkey_helper(&priv_keys);

        let signature = sign_helper(priv_keys, X_agg.clone(), L);
        assert_eq!(true, signature.verify(b"message to sign".to_vec(), X_agg));
    }
}
