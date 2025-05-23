//! Dogecoin module.
//!
//! This module provides support for de/serialization, parsing and execution on data structures and
//! network messages related to Dogecoin.

use crate::block::Header;
use crate::block::TxMerkleNode;
use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{Read, Write};
use crate::prelude::*;
use crate::{io, BlockHash, Transaction};

/// AuxPow version bit, see https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/pureheader.h#L23
pub const VERSION_AUXPOW: i32 = 1 << 8;

fn is_auxpow(header: Header) -> bool {
    (header.version.to_consensus() & VERSION_AUXPOW) != 0
}

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
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }
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
