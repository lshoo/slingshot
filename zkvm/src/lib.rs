#![deny(missing_docs)]
//! ZkVM implementation.

#[macro_use]
extern crate failure;
extern crate serde;

mod blockchain;
mod constraints;
mod contract;
mod encoding;
mod errors;
mod merkle;
mod ops;
mod point_ops;
mod predicate;
mod program;
mod prover;
mod scalar_witness;
mod transcript;
mod tx;
mod types;
mod verifier;
mod vm;

pub use self::constraints::{Commitment, Constraint, Expression, Variable};
pub use self::contract::{Anchor, Contract, ContractID, PortableItem};
pub use self::errors::VMError;
pub use self::merkle::{MerkleItem, MerkleNeighbor, MerkleTree};
pub use self::ops::{Instruction, Opcode};
pub use self::predicate::{Predicate, PredicateTree};
pub use self::program::{Program, ProgramItem};
pub use self::prover::Prover;
pub use self::scalar_witness::ScalarWitness;
pub use self::transcript::TranscriptProtocol;
pub use self::tx::{Tx, TxEntry, TxHeader, TxID, TxLog, UnsignedTx, VerifiedTx};
pub use self::types::{Data, Item, Value, WideValue};
pub use self::verifier::Verifier;

pub use self::blockchain::*;

pub use musig::{Multikey, Signature, VerificationKey};
