use bulletproofs::BulletproofGens;
use merlin::Transcript;

use super::errors::BlockchainError;
use super::state::BlockchainState;
use crate::{ContractID, MerkleTree, Tx, TxID, TxLog, Verifier};

#[derive(Clone, PartialEq)]
pub struct BlockID(pub [u8; 32]);

#[derive(Clone)]
pub struct BlockHeader {
    pub version: u64,
    pub height: u64,
    pub prev: BlockID,
    pub timestamp_ms: u64,
    pub txroot: [u8; 32],
    pub utxoroot: [u8; 32],
    pub ext: Vec<u8>,
}

impl BlockHeader {
    pub fn id(&self) -> BlockID {
        let mut t = Transcript::new(b"ZkVM.blockheader");
        t.commit_u64(b"version", self.version);
        t.commit_u64(b"height", self.height);
        t.commit_bytes(b"previd", &self.prev.0);
        t.commit_u64(b"timestamp_ms", self.timestamp_ms);
        t.commit_bytes(b"txroot", &self.txroot);
        t.commit_bytes(b"utxoroot", &self.utxoroot);
        t.commit_bytes(b"ext", &self.ext);

        let mut result = [0u8; 32];
        t.challenge_bytes(b"id", &mut result);
        BlockID(result)
    }

    pub fn make_initial(timestamp_ms: u64, utxoroot: [u8; 32]) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 1,
            prev: BlockID([0; 32]),
            timestamp_ms: timestamp_ms,
            txroot: MerkleTree::root(b"ZkVM.txroot", &[]),
            utxoroot: utxoroot,
            ext: Vec::new(),
        }
    }

    pub fn validate(&self, prev: &Self) -> Result<(), BlockchainError> {
        check(
            self.version >= prev.version,
            BlockchainError::VersionReversion,
        )?;
        check(
            self.version > 1 || self.ext.len() == 0,
            BlockchainError::IllegalExtension,
        )?;
        check(self.height == prev.height + 1, BlockchainError::BadHeight)?;
        check(self.prev == prev.id(), BlockchainError::MismatchedPrev)?;
        check(
            self.timestamp_ms > prev.timestamp_ms,
            BlockchainError::BadBlockTimestamp,
        )?;
        // TODO: execute transaction list and verify txroot
        Ok(())
    }
}

fn check(cond: bool, err: BlockchainError) -> Result<(), BlockchainError> {
    if !cond {
        return Err(err);
    }
    Ok(())
}

pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn validate(
        &self,
        prev: &BlockHeader,
        bp_gens: &BulletproofGens,
    ) -> Result<Vec<TxLog>, BlockchainError> {
        self.header.validate(prev)?;

        let mut txlogs: Vec<TxLog> = Vec::with_capacity(self.txs.len());
        let mut txids: Vec<TxID> = Vec::with_capacity(self.txs.len());

        for tx in self.txs.iter() {
            if tx.header.mintime_ms > self.header.timestamp_ms
                || self.header.timestamp_ms > tx.header.maxtime_ms
            {
                return Err(BlockchainError::BadTxTimestamp);
            }
            if self.header.version == 1 && tx.header.version != 1 {
                return Err(BlockchainError::BadTxVersion);
            }

            match Verifier::verify_tx(tx, bp_gens) {
                Ok(verified) => {
                    let txid = TxID::from_log(&verified.log);
                    txids.push(txid);
                    txlogs.push(verified.log);
                }
                Err(err) => return Err(BlockchainError::TxValidation(err)),
            }
        }

        let merkle_tree = MerkleTree::build(b"transaction_ids", &txids[..]);
        let txroot = merkle_tree.hash();
        if &self.header.txroot != txroot {
            return Err(BlockchainError::TxrootMismatch);
        }

        Ok(txlogs)
    }

    /// Constructs a block from a list of transactions
    pub fn make(
        state: BlockchainState,
        txs: Vec<Tx>,
        block_version: u64,
        timestamp_ms: u64,
        ext: Vec<u8>,
    ) -> Result<Self, BlockchainError> {
        let bp_gens = BulletproofGens::new(1, 256);
        let mut new_state = state.clone();
        let txids = txs
            .iter()
            .map(|tx| {
                let (txid, txlog) =
                    BlockchainState::execute_tx(&tx, &bp_gens, block_version, timestamp_ms)?;
                new_state
                    .apply_txlog(&txlog)
                    .map_err(|e| BlockchainError::TxValidation(e))?;
                Ok(txid)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            header: BlockHeader {
                version: block_version,
                height: state.tip.height + 1,
                prev: state.tip.id(),
                timestamp_ms: timestamp_ms,
                txroot: MerkleTree::root(b"ZkVM.txroot", &txids),
                utxoroot: Root::utxo(&new_state.utxos).0,
                ext: ext,
            },
            txs: txs,
        })
    }
}
