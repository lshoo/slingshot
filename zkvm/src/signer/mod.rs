#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
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
    G: RistrettoPoint,
    transcript: Transcript,
    X_agg: PubKey,
    L: PubKeyHash,
    m: Vec<u8>,
}

impl MultiKey {
    pub fn aggregate(&self, transcript: &mut Transcript) -> (PubKey, PubKeyHash) {
        let L = {
            let mut L_transcript = transcript.clone();
            for X_i in &self.0 {
                L_transcript.commit_point(b"X_i.L", &X_i.0.compress());
            }
            L_transcript.challenge_scalar(b"L")    
        };

        let mut X = RistrettoPoint::default();
        for X_i in &self.0 {
            let a_i = {
                let mut a_i_transcript = transcript.clone();
                a_i_transcript.commit_scalar(b"L", &L);
                a_i_transcript.commit_point(b"X_i", &X_i.0.compress());
                a_i_transcript.challenge_scalar(b"a_i")
            };          
        }

        (PubKey(X), PubKeyHash(L))
    }
}

impl Signature {
    pub fn verify(&self, shared: Shared) -> bool {
        // Make c = H(X_agg, R, m)
        let c = {
            let mut hash_transcript = shared.transcript.clone();
            hash_transcript.commit_point(b"X_agg", &shared.X_agg.0.compress());
            hash_transcript.commit_point(b"R", &self.R.compress());
            hash_transcript.commit_bytes(b"m", &shared.m);
            hash_transcript.challenge_scalar(b"c")
        };

        // Check sG = R + c * X_agg
        self.s * shared.G == self.R + c * shared.X_agg.0
    }
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
            230, 10, 31, 242, 52, 253, 170, 11, 188, 32, 16, 75, 197, 68, 202, 134, 44, 2, 170, 6,
            233, 235, 108, 137, 125, 139, 72, 188, 48, 243, 41, 47,
        ]);
        let expected_pub_key_hash = Scalar::from_bits([
            60, 100, 150, 203, 200, 157, 0, 177, 105, 36, 13, 89, 221, 235, 157, 208, 57, 177, 210,
            199, 101, 182, 128, 5, 125, 101, 109, 94, 125, 160, 223, 2,
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
        let mut transcript = Transcript::new(b"sign msg test");
        multi_key.aggregate(&mut transcript)
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

        let shared = Shared {
            G: RISTRETTO_BASEPOINT_POINT,
            transcript: Transcript::new(b"sign msg test"),
            X_agg,
            L,
            m: b"message to sign".to_vec(),
        };

        sign_helper(priv_keys, shared);
    }

    fn sign_helper(priv_keys: Vec<PrivKey>, shared: Shared) -> Signature {
        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .map(|x_i| PartyAwaitingPrecommitments::new(x_i, shared.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone()))
            .unzip();

        let pub_keys: Vec<_> = priv_keys
            .iter()
            .map(|priv_key| PubKey(priv_key.0 * shared.G))
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

        let shared = Shared {
            G: RISTRETTO_BASEPOINT_POINT,
            transcript: Transcript::new(b"sign msg test"),
            X_agg,
            L,
            m: b"message to sign".to_vec(),
        };

        let signature = sign_helper(priv_keys, shared.clone());
        assert_eq!(true, signature.verify(shared.clone()));
    }
}
