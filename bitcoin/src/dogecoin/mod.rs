//! Dogecoin module.
//!
//! This module provides support for de/serialization, parsing and execution on data structures and
//! network messages related to Dogecoin.

use hashes::{sha256d, Hash};
use units::Amount;

use crate::block::{Header, TxMerkleNode};
use crate::consensus::{encode, Decodable, Encodable, Params};
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{Read, Write};
use crate::opcodes::all::OP_CHECKSIG;
use crate::prelude::*;
use crate::{
    absolute, block, io, script, transaction, BlockHash, CompactTarget, Network, OutPoint,
    Sequence, Transaction, TxIn, TxOut, Witness,
};

#[rustfmt::skip]
const DOGECOIN_GENESIS_OUTPUT_PK: [u8; 65] = [
    0x04,
    0x01, 0x84, 0x71, 0x0f, 0xa6, 0x89, 0xad, 0x50,
    0x23, 0x69, 0x0c, 0x80, 0xf3, 0xa4, 0x9c, 0x8f,
    0x13, 0xf8, 0xd4, 0x5b, 0x8c, 0x85, 0x7f, 0xbc,
    0xbc, 0x8b, 0xc4, 0xa8, 0xe4, 0xd3, 0xeb, 0x4b,
    0x10, 0xf4, 0xd4, 0x60, 0x4f, 0xa0, 0x8d, 0xce,
    0x60, 0x1a, 0xaf, 0x0f, 0x47, 0x02, 0x16, 0xfe,
    0x1b, 0x51, 0x85, 0x0b, 0x4a, 0xcf, 0x21, 0xb1,
    0x79, 0xc4, 0x50, 0x70, 0xac, 0x7b, 0x03, 0xa9
];

/// AuxPow version bit, see <https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/pureheader.h#L23>
pub const VERSION_AUXPOW: i32 = 1 << 8;

fn is_auxpow(header: Header) -> bool { (header.version.to_consensus() & VERSION_AUXPOW) != 0 }

/// Data for merge-mining AuxPoW.
///
/// It contains the parent block's coinbase tx that can be verified to be in the parent block.
/// The transaction's input contains the hash to the actual merge-mined block.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AuxPow {
    /// The parent block's coinbase tx.
    pub coinbase_tx: Transaction,
    /// The parent block's hash.
    pub parent_hash: BlockHash,
    /// The Merkle branch linking the coinbase tx to the parent block's Merkle root.
    pub coinbase_branch: Vec<TxMerkleNode>,
    /// The index of the coinbase tx in the Merkle tree.
    pub coinbase_index: i32,
    /// The Merkle branch linking the merge-mined block to the coinbase tx.
    pub blockchain_branch: Vec<TxMerkleNode>,
    /// The index of the merged-mined block in the Merkle tree.
    pub blockchain_index: i32,
    /// Parent block header (on which the PoW is done).
    pub parent_block: Header,
}

impl_consensus_encoding!(
    AuxPow,
    coinbase_tx,
    parent_hash,
    coinbase_branch,
    coinbase_index,
    blockchain_branch,
    blockchain_index,
    parent_block
);

/// Dogecoin block.
///
/// A collection of transactions with an attached proof of work.
/// The AuxPoW is present if the block was mined using merge-mining.
///
/// See [Bitcoin Wiki: Block][wiki-block] and [Bitcoin Wiki: Merged_mining_specification][merge-mining]
/// for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
/// [merge-mining]: https://en.bitcoin.it/wiki/Merged_mining_specification
///
/// ### Dogecoin Core References
///
/// * [CBlock definition](https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/block.h#L65)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// AuxPoW structure, present if merged mining was used to mine this block.
    pub auxpow: Option<AuxPow>,
    /// List of transactions contained in the block.
    pub txdata: Vec<Transaction>,
}

impl Block {
    /// Returns the block hash computed as SHA256d(header).
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }
}

impl Decodable for Block {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let header: Header = Decodable::consensus_decode_from_finite_reader(r)?;
        let auxpow = if is_auxpow(header) {
            Some(Decodable::consensus_decode_from_finite_reader(r)?)
        } else {
            None
        };
        let txdata = Decodable::consensus_decode_from_finite_reader(r)?;

        Ok(Self { header, auxpow, txdata })
    }
}

impl Encodable for Block {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        if let Some(ref auxpow) = self.auxpow {
            len += auxpow.consensus_encode(w)?;
        }
        len += self.txdata.consensus_encode(w)?;
        Ok(len)
    }
}

/// Constructs and returns the coinbase (and only) transaction of the Dogecoin genesis block.
pub fn dogecoin_genesis_tx(params: &Params) -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let (in_script, out_script) = {
        match params.network {
            Network::Dogecoin | Network::DogecoinTestnet | Network::DogecoinRegtest => (
                script::Builder::new()
                    .push_int(486604799)
                    .push_int_non_minimal(4)
                    .push_slice(b"Nintondo")
                    .into_script(),
                script::Builder::new()
                    .push_slice(DOGECOIN_GENESIS_OUTPUT_PK)
                    .push_opcode(OP_CHECKSIG)
                    .into_script(),
            ),
            _ => unreachable!(),
        }
    };

    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });
    ret.output.push(TxOut { value: Amount::from_sat(88 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn dogecoin_genesis_block(params: impl AsRef<Params>) -> crate::Block {
    let params = params.as_ref();
    let txdata = vec![dogecoin_genesis_tx(params)];
    let hash: sha256d::Hash = txdata[0].compute_txid().into();
    let merkle_root: crate::TxMerkleNode = hash.into();

    match params.network {
        Network::Dogecoin => crate::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1386325540,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 99943,
            },
            txdata,
        },
        Network::DogecoinTestnet => crate::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1391503289,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 997879,
            },
            txdata,
        },
        Network::DogecoinRegtest => crate::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
            },
            txdata,
        },
        _ => unreachable!(),
    }
}
