// SPDX-License-Identifier: Apache-2.0

//! Dogecoin module.
//!
//! This module provides support for de/serialization, parsing and execution on data structures and
//! network messages related to Dogecoin.

// TODO: format using formatter
pub mod address;
pub mod constants;
pub mod params;

pub use address::*;

use crate::block::{Header as PureHeader, TxMerkleNode, Version};
use crate::consensus::{encode, Decodable, Encodable};
use crate::dogecoin::params::Params;
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{Read, Write};
use crate::p2p::Magic;
use crate::prelude::*;
use crate::{io, BlockHash, Transaction};
use core::fmt;
use hashes::Hash;
use std::ops::{Deref, DerefMut};

/// AuxPow version bit, see <https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/pureheader.h#L23>
pub const VERSION_AUXPOW: i32 = 1 << 8;

const MERGED_MINING_HEADER: [u8; 4] = [0xfa, 0xbe, b'm', b'm'];

/// AuxPow validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxPowValidationError {
    /// Aux POW does not originate from a valid coinbase transaction
    AuxPowNotFromCoinbase,
    /// Chain ID is duplicated in both parent and current block
    ParentHasSameChainId,
    /// Aux POW blockchain merkle branch is too long
    ChainMerkleBranchTooLong,
    /// Aux POW coinbase transaction has invalid merkle proof
    InvalidCoinbaseMerkleProof,
    /// Aux POW coinbase transaction has no inputs
    CoinbaseHasNoInputs,
    /// Invalid script in coinbase transaction
    InvalidAuxPowCoinbaseScript(AuxPowCoinbaseScriptValidationError)
}

impl fmt::Display for AuxPowValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuxPowValidationError::AuxPowNotFromCoinbase =>
                write!(f, "Aux POW does not originate from a valid coinbase transaction"),
            AuxPowValidationError::ParentHasSameChainId =>
                write!(f, "Chain ID duplicated in both parent and current block"),
            AuxPowValidationError::ChainMerkleBranchTooLong =>
                write!(f, "Aux POW blockchain merkle branch too long"),
            AuxPowValidationError::InvalidCoinbaseMerkleProof =>
                write!(f, "Aux POW coinbase transaction has invalid merkle proof"),
            AuxPowValidationError::CoinbaseHasNoInputs =>
                write!(f, "Aux POW coinbase transaction has no inputs"),
            AuxPowValidationError::InvalidAuxPowCoinbaseScript(err) =>
                write!(f, "{}", err),
        }
    }
}

/// AuxPow coinbase script validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxPowCoinbaseScriptValidationError {
    /// The blockchain merkle root is missing from the coinbase transaction
    MissingMerkleRoot,
    /// There are multiple merged mining headers in the coinbase transaction
    MultipleHeaders,
    /// Merged mining header is not just before the blockchain merkle root
    HeaderNotAdjacent,
    /// Blockchain merkle root must start in the first 20 bytes of the coinbase transaction
    LegacyRootTooFar,
    /// Missing blockchain merkle tree size and nonce in the coinbase transaction
    MissingMerkleSizeAndNonce,
    /// Blockchain merkle branch size does not match merkle size in the coinbase transaction
    MerkleSizeMismatch,
    /// Blockchain index does not match expected value derived from nonce and chain ID
    InvalidChainIndex
}

impl fmt::Display for AuxPowCoinbaseScriptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuxPowCoinbaseScriptValidationError::MissingMerkleRoot =>
                write!(f, "Aux POW missing blockchain merkle root in coinbase transaction"),
            AuxPowCoinbaseScriptValidationError::MultipleHeaders =>
                write!(f, "Aux POW with multiple merged mining headers in coinbase transaction"),
            AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent =>
                write!(f, "Aux POW merged mining header not just before blockchain merkle root"),
            AuxPowCoinbaseScriptValidationError::LegacyRootTooFar =>
                write!(f, "Aux POW blockchain merkle root must start in first 20 bytes of the coinbase transaction"),
            AuxPowCoinbaseScriptValidationError::MissingMerkleSizeAndNonce =>
                write!(f, "Aux POW missing blockchain merkle tree size and nonce in coinbase transaction"),
            AuxPowCoinbaseScriptValidationError::MerkleSizeMismatch =>
                write!(f, "Aux POW merkle blockchain branch size does not match merkle size in coinbase transaction"),
            AuxPowCoinbaseScriptValidationError::InvalidChainIndex =>
                write!(f, "Aux POW blockchain index does not match expected value derived from nonce and chain ID"),
        }
    }
}

impl Into<AuxPowValidationError> for AuxPowCoinbaseScriptValidationError {
    fn into(self) -> AuxPowValidationError {
        AuxPowValidationError::InvalidAuxPowCoinbaseScript(self)
    }
}

/// Data for merged-mining AuxPow.
///
/// It contains the parent block's coinbase tx that can be verified to be in the parent block.
/// The transaction's input contains the hash to the actual merged-mined block.
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
    /// The index of the coinbase tx in the Merkle tree. Must be 0.
    pub coinbase_index: i32,
    /// The Merkle branch linking the merged-mined header to the coinbase tx.
    pub blockchain_branch: Vec<TxMerkleNode>,
    /// The index of the merged-mined header in the Merkle tree.
    pub blockchain_index: i32,
    /// Parent block header on which the PoW is done.
    pub parent_block_header: PureHeader,
}

impl_consensus_encoding!(
    AuxPow,
    coinbase_tx,
    parent_hash,
    coinbase_branch,
    coinbase_index,
    blockchain_branch,
    blockchain_index,
    parent_block_header
);

impl AuxPow {
    /// Helper method to produce SHA256D(left + right) - same as [`crate::merkle_tree::PartialMerkleTree::parent_hash`]
    fn parent_hash(left: TxMerkleNode, right: TxMerkleNode) -> TxMerkleNode {
        let mut encoder = TxMerkleNode::engine();
        left.consensus_encode(&mut encoder).expect("engines don't error");
        right.consensus_encode(&mut encoder).expect("engines don't error");
        TxMerkleNode::from_engine(encoder)
    }

    /// Computes the merkle root from a hash and its merkle branch proof.
    pub fn compute_merkle_root(
        hash: BlockHash,
        branch: &[TxMerkleNode],
        index: i32,
    ) -> TxMerkleNode {
        let mut result_hash = TxMerkleNode::from_byte_array(hash.to_byte_array());
        let mut index = index;

        for branch_hash in branch {
            if index & 1 == 1 {
                // Hash is on the right, branch element on the left
                result_hash = Self::parent_hash(*branch_hash, result_hash);
            } else {
                // Hash is on the left, branch element on the right
                result_hash = Self::parent_hash(result_hash, *branch_hash);
            }
            index >>= 1;
        }

        result_hash
    }

    /// Validates the merged mining header and merkle tree data in the coinbase script.
    ///
    /// The validation includes:
    ///
    /// 1. Merkle root: Ensures the blockchain merkle root is present
    /// 2. Merged mining header: Ensures the merged mining header (0xfabe6d6d) is present
    /// 3. Merged mining header uniqueness: Ensures only one merged mining header exists
    /// 4. Merkle tree: Verifies that the merkle tree size matches the blockchain branch size
    /// 5. Merkle tree index: Verifies the AuxPow header's index in the blockchain merkle tree
    ///
    /// # Arguments
    ///
    /// * `script` - The coinbase transaction input script containing the merge mining data
    /// * `blockchain_merkle_root` - The merkle root of the headers of the merged-mined blockchains
    /// * `chain_id` - Chain ID of the blockchain used for deterministic index calculation
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validations pass, or an `AuxPowValidationError` describing the failure
    ///
    /// # Merge Mining Protocol
    ///
    /// The coinbase script embeds merge mining data in this format:
    /// ```text
    /// [...prefix] [merge_mining_header] [blockchain_merkle_root] [merkle_size] [merkle_nonce] [suffix...]
    /// ```
    /// Where:
    /// - `merge_mining_header`: 4-byte magic header (0xfabe6d6d)
    /// - `blockchain_merkle_root`: 32-byte root of the blockchain merkle tree
    /// - `merkle_size`: 4-byte little-endian merkle tree size (2^height)
    /// - `merkle_nonce`: 4-byte little-endian nonce to calculate deterministic indices of headers into merkle tree
    fn check_merged_mining_coinbase_script(
        &self,
        script: &[u8],
        blockchain_merkle_root: &[u8; 32],
        chain_id: i32,
    ) -> Result<(), AuxPowCoinbaseScriptValidationError> {
        let root_pos = Self::find_bytes(script, blockchain_merkle_root)
            .ok_or(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot)?;

        match Self::find_bytes(script, &MERGED_MINING_HEADER) {
            Some(header_pos) => {
                // Check for multiple headers
                let search_start = header_pos + MERGED_MINING_HEADER.len();
                if Self::find_bytes(&script[search_start..], &MERGED_MINING_HEADER).is_some() {
                    return Err(AuxPowCoinbaseScriptValidationError::MultipleHeaders);
                }
                // Check that header immediately precedes merkle root
                if header_pos + MERGED_MINING_HEADER.len() != root_pos {
                    return Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent);
                }
            }
            None => {
                // For backward compatibility: merkle root must start early in coinbase
                // 8-12 bytes are enough to encode extraNonce and nBits
                if root_pos > 20 {
                    return Err(AuxPowCoinbaseScriptValidationError::LegacyRootTooFar);
                }
            }
        }

        let pos_after_root = root_pos + blockchain_merkle_root.len();
        let remaining_script = &script[pos_after_root..];
        
        if remaining_script.len() < 8 {
            return Err(AuxPowCoinbaseScriptValidationError::MissingMerkleSizeAndNonce);
        }

        let size_bytes = [remaining_script[0], remaining_script[1], remaining_script[2], remaining_script[3]];
        let size = u32::from_le_bytes(size_bytes);
        
        let merkle_height = self.blockchain_branch.len();
        if size != (1u32 << merkle_height) {
            return Err(AuxPowCoinbaseScriptValidationError::MerkleSizeMismatch);
        }

        let nonce_bytes = [remaining_script[4], remaining_script[5], remaining_script[6], remaining_script[7]];
        let nonce = u32::from_le_bytes(nonce_bytes);
        
        let expected_index = Self::get_expected_index(nonce, chain_id, merkle_height);
        if self.blockchain_index != expected_index {
            return Err(AuxPowCoinbaseScriptValidationError::InvalidChainIndex);
        }

        Ok(())
    }

    /// Returns the byte offset of the first occurrence of `needle` in `haystack`.
    /// If the `needle` is not found, returns `None`.
    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Calculate the expected index of the AuxPow block header in the blockchain merkle tree.
    ///
    /// Given the merkle tree size, nonce, and chain ID, computes a pseudo-random slot in the blockchain
    /// merkle tree. This prevents replay attacks in merge mining by assigning each blockchain a
    /// deterministic position in the blockchain merkle tree.
    /// 
    /// Ref: <https://github.com/dogecoin/dogecoin/blob/51cbc1fd5d0d045dda2ad84f53572bbf524c6a8e/src/auxpow.cpp#L164>
    pub fn get_expected_index(nonce: u32, chain_id: i32, merkle_height: usize) -> i32 {
        // The original C++ implementation mentions that this computation can overflow but that
        // this is not an issue. In C++, unsigned integer overflows automatically wrap around.
        // To replicate the wrapping behavior, we use `wrapping_mul` and `wrapping_add`.

        let mut rand = nonce;
        rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
        rand = rand.wrapping_add(chain_id as u32);
        rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
        
        (rand % (1u32 << merkle_height)) as i32
    }

    /// Validates the AuxPow structure for merge mining.
    ///
    /// The validation ensures:
    /// - The coinbase transaction is properly positioned in the parent block
    /// - The merged mining header and blockchain merkle root are correctly embedded in the coinbase script
    /// - The blockchain index matches the expected deterministic position
    /// - Chain ID constraints are enforced to prevent cross-chain attacks
    ///
    /// Ref: <https://github.com/dogecoin/dogecoin/blob/51cbc1fd5d0d045dda2ad84f53572bbf524c6a8e/src/auxpow.cpp#L81>
    ///
    /// # Arguments
    ///
    /// * `aux_block_hash` - Hash of the AuxPow block being merged-mined
    /// * `chain_id` - Chain ID of the auxiliary blockchain (e.g. 98 for Dogecoin)
    /// * `strict_chain_id` - If true, enforces that parent and auxiliary chains have different chain IDs
    ///
    /// # Returns
    ///
    /// `Ok(())` if the AuxPoW is valid, or an `AuxPowValidationError` describing the validation failure
    pub fn check(&self, aux_block_hash: BlockHash, chain_id: i32, strict_chain_id: bool) -> Result<(), AuxPowValidationError> {
        if self.coinbase_index != 0 {
            return Err(AuxPowValidationError::AuxPowNotFromCoinbase);
        }

        if strict_chain_id && get_chain_id(&self.parent_block_header) == chain_id {
            return Err(AuxPowValidationError::ParentHasSameChainId);
        }

        if self.blockchain_branch.len() > 30 {
            return Err(AuxPowValidationError::ChainMerkleBranchTooLong);
        }

        let blockchain_merkle_root = Self::compute_merkle_root(aux_block_hash, &self.blockchain_branch, self.blockchain_index); // TODO: correct endianness

        let coinbase_hash = self.coinbase_tx.compute_txid();
        let transactions_merkle_root = Self::compute_merkle_root(
            BlockHash::from_byte_array(coinbase_hash.to_byte_array()),
            &self.coinbase_branch,
            self.coinbase_index
        );

        if transactions_merkle_root != self.parent_block_header.merkle_root {
            return Err(AuxPowValidationError::InvalidCoinbaseMerkleProof);
        }

        if self.coinbase_tx.input.is_empty() {
            return Err(AuxPowValidationError::CoinbaseHasNoInputs);
        }

        let script = &self.coinbase_tx.input[0].script_sig;

        self.check_merged_mining_coinbase_script(script.as_bytes(), &blockchain_merkle_root.to_byte_array(), chain_id).map_err(AuxPowValidationError::InvalidAuxPowCoinbaseScript)?;

        Ok(())
    }
}


/// Dogecoin block header.
///
/// ### Dogecoin Core References
///
/// * [CBlockHeader definition](https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/primitives/block.h#L23)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block header without AuxPow information.
    pub pure_header: PureHeader,
    /// AuxPoW structure, present if merged mining was used to mine this block.
    pub aux_pow: Option<AuxPow>,
}

impl Deref for Header {
    type Target = PureHeader;
    fn deref(&self) -> &Self::Target {
        &self.pure_header
    }
}

impl DerefMut for Header {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pure_header
    }
}

/// Checks if a block header indicates it was merged mined and contains AuxPow information.
pub fn has_auxpow(header: &PureHeader) -> bool {
    (header.version.to_consensus() & VERSION_AUXPOW) != 0
}

/// Extracts the chain ID from the block header's version field.
pub fn get_chain_id(header: &PureHeader) -> i32 {
    header.version.to_consensus() >> 16
}

/// Determines if a block header represents a legacy (pre-AuxPoW) block.
pub fn is_legacy(header: &PureHeader) -> bool {
    header.version == Version::ONE
        // Random v2 block with no AuxPoW, treat as legacy
        || (header.version == Version::TWO && get_chain_id(header) == 0)
}

/// Extracts the base version number from a block header, removing AuxPoW and chain ID bits.
pub fn base_version(header: &PureHeader) -> i32 {
    header.version.to_consensus() % VERSION_AUXPOW
}

impl Header {
    /// Creates a Dogecoin header from a block header without AuxPoW data.
    pub fn new_from_pure_header(pure_header: PureHeader) -> Self {
        Self { pure_header, aux_pow: None }
    }
}

impl Decodable for Header {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let pure_header: PureHeader = Decodable::consensus_decode_from_finite_reader(r)?;
        let aux_pow = if has_auxpow(&pure_header) {
            Some(Decodable::consensus_decode_from_finite_reader(r)?)
        } else {
            None
        };

        Ok(Self { pure_header, aux_pow })
    }
}

impl Encodable for Header {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.pure_header.consensus_encode(w)?;
        if let Some(ref aux_pow) = self.aux_pow {
            len += aux_pow.consensus_encode(w)?;
        }
        Ok(len)
    }
}

/// Dogecoin block.
///
/// A collection of transactions with an attached proof of work.
/// The AuxPoW data is present in `header` if the block was mined using merged-mining.
///
/// See [Bitcoin Wiki: Block][wiki-block] and [Bitcoin Wiki: Merged_mining_specification][merged-mining]
/// for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
/// [merged-mining]: https://en.bitcoin.it/wiki/Merged_mining_specification
///
/// ### Dogecoin Core References
///
/// * [CBlock definition](https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/block.h#L65)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The Dogecoin block header.
    pub header: Header,
    /// List of transactions contained in the block.
    pub txdata: Vec<Transaction>,
}

impl Block {
    /// Returns the block hash computed as SHA256d(header).
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Returns the block hash using the scrypt hash function.
    pub fn block_hash_with_scrypt(&self) -> BlockHash { self.header.block_hash_with_scrypt() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Compute merkle root of the transaction list in this block.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self
            .txdata
            .iter()
            .map(|obj| obj.compute_txid().to_raw_hash());
        crate::merkle_tree::calculate_root(hashes).map(|h| h.into())
    }
}

impl_consensus_encoding!(Block, header, txdata);

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Dogecoin.
    Dogecoin,
    /// Dogecoin's testnet network.
    Testnet,
    /// Dogecoin's regtest network.
    Regtest,
}

impl Network {
    /// Returns the associated network parameters.
    pub const fn params(self) -> &'static Params {
        match self {
            Network::Dogecoin => &Params::DOGECOIN,
            Network::Testnet => &Params::TESTNET,
            Network::Regtest => &Params::REGTEST,
        }
    }

    /// Return the magic bytes for the given network.
    pub fn magic(self) -> Magic {
        match self {
            Network::Dogecoin => Magic::from_bytes([0xC0, 0xC0, 0xC0, 0xC0]),
            Network::Testnet => Magic::from_bytes([0xFC, 0xC1, 0xB7, 0xDC]),
            Network::Regtest => Magic::from_bytes([0xFA, 0xBF, 0xB5, 0xDA]),
        }
    }
}

impl AsRef<Params> for Network {
    fn as_ref(&self) -> &Params {
        self.params()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Network::Dogecoin => write!(f, "dogecoin"),
            Network::Testnet => write!(f, "testnet"),
            Network::Regtest => write!(f, "regtest"),
        }
    }
}

impl core::str::FromStr for Network {
    type Err = crate::network::ParseNetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dogecoin" => Ok(Network::Dogecoin),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(crate::network::ParseNetworkError(s.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::block::{ValidationError, Version};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::{CompactTarget, Target, Work};
    use crate::{Network as BitcoinNetwork};


    #[test]
    fn dogecoin_block_test() {
        // Mainnet Dogecoin block 5794c80b80d9c33e0737a5353cd52b1f097f61d8d2b9f471e1702345080e0002
        let some_block = hex!("01000000c76fe7f8ec09989d32b7907966fbd347134f80a7b71efce55fec502aa126ba3894b3065289ff8ba1ab4e8391771174d47cf2c974ebd24a1bdafd6c107d5a7a207d78bb52de8f001c00da8c3c0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2602bc6d062f503253482f047178bb5208f8042975030000000d2f7374726174756d506f6f6c2f000000000100629b29c45500001976a91450e9fe87c705dcd4b7523b47e3314c2115f5d5df88ac0000000001000000015f48fabf4425324df2b5e58f4e9c771297f76f5fa37db7556f6fc1d22742da1f010000006a473044022062d29d2d26f7d826e7b72257486e294d284832743c7803a2901eb07e326b25a002207efc391b0f4e724c9d518075c0e056cc425540f845b0fd419ba8a9d49d69288301210297a2568525760a98454d84f5e5adba9fd0a41726a6fb774ddc407279e41e2061ffffffff0240bab598200000001976a91401348a2b83aeb6b1ba2a174a1a40b7c75fbeb12088ac0040be40250000001976a914025407d928ef333979d064ae233353d80e29d58c88ac00000000");
        let cutoff_block = hex!("01000000c76fe7f8ec09989d32b7907966fbd347134f80a7b71efce55fec502aa126ba3894b3065289ff8ba1ab4e8391771174d47cf2c974ebd24a1bdafd6c107d5a7a207d78bb52de8f001c00da8c3c0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2602bc6d062f503253482f047178bb5208f8042975030000000d2f7374726174756d506f6f6c2f000000000100629b29c45500001976a91450e9fe87c705dcd4b7523b47e3314c2115f5d5df88ac0000000001000000015f48fabf4425324df2b5e58f4e9c771297f76f5fa37db7556f6fc1d22742da1f010000006a473044022062d29d2d26f7d826e7b72257486e294d284832743c7803a2901eb07e326b25a002207efc391b0f4e724c9d518075c0e056cc425540f845b0fd419ba8a9d49d69288301210297a2568525760a98454d84f5e5adba9fd0a41726a6fb774ddc407279e41e2061ffffffff0240bab598200000001976a91401348a2b83aeb6b1ba2a174a1a40b7c75fbeb12088ac0040be40250000001976a914025407d928ef333979d064ae233353d80e29d58c88ac");

        let currhash = hex!("02000e08452370e171f4b9d2d8617f091f2bd53c35a537073ec3d9800bc89457");
        let prevhash = hex!("c76fe7f8ec09989d32b7907966fbd347134f80a7b71efce55fec502aa126ba38");
        let merkle = hex!("94b3065289ff8ba1ab4e8391771174d47cf2c974ebd24a1bdafd6c107d5a7a20");
        let work = Work::from(0x1c788001c78_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(serialize(&real_decode.header.block_hash()), currhash);
        assert_eq!(real_decode.header.version, Version::ONE);
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        // assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1388017789);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(469798878));
        assert_eq!(real_decode.header.nonce, 1015863808);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow_with_scrypt(real_decode.header.target()).unwrap(),
            real_decode.header.block_hash_with_scrypt()
        );
        // Bitcoin network is used because Dogecoin's difficulty calculation is based on Bitcoin's,
        // which uses Bitcoin's `max_attainable_target` value
        assert_eq!(real_decode.header.difficulty(BitcoinNetwork::Bitcoin), 455);
        assert_eq!(real_decode.header.difficulty_float(), 455.52430084170516);

        assert_eq!(serialize(&real_decode), some_block);
    }

    #[test]
    fn validate_pow_with_scrypt_test() {
        let some_header = hex!("01000000c76fe7f8ec09989d32b7907966fbd347134f80a7b71efce55fec502aa126ba3894b3065289ff8ba1ab4e8391771174d47cf2c974ebd24a1bdafd6c107d5a7a207d78bb52de8f001c00da8c3c");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow_with_scrypt(some_header.target()).unwrap(),
            some_header.block_hash_with_scrypt()
        );

        // test with zero target
        match some_header.validate_pow_with_scrypt(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow_with_scrypt"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.nonce += 1;
        match invalid_header.validate_pow_with_scrypt(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow_with_scrypt"),
        }
    }

    #[test]
    fn block_hash_with_scrypt_test() {
        struct Test {
            input: Vec<u8>,
            output: Vec<u8>,
            output_str: &'static str,
        }

        let tests = vec![
            // Example from <https://litecoin.info/docs/key-concepts/proof-of-work>
            Test {
                input: hex!("01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4"),
                output: vec![217, 235, 134, 99, 255, 236, 36, 28, 47, 177, 24, 173, 183, 222, 151, 168, 44, 128, 59, 111, 244, 109, 87, 102, 121, 53, 200, 16, 1, 0, 0, 0],
                output_str: "0000000110c8357966576df46f3b802ca897deb7ad18b12f1c24ecff6386ebd9"
            },
            // Examples from <https://github.com/dogecoin/ltc-scrypt/blob/main/test.py>
            Test {
                input: hex!("020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659"),
                output: vec![6, 88, 152, 215, 171, 45, 170, 130, 53, 205, 218, 149, 17, 210, 72, 243, 1, 11, 94, 17, 246, 130, 248, 7, 65, 239, 43, 0, 0, 0, 0, 0],
                output_str: "00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806",
            },
            Test {
                input: hex!("0200000011503ee6a855e900c00cfdd98f5f55fffeaee9b6bf55bea9b852d9de2ce35828e204eef76acfd36949ae56d1fbe81c1ac9c0209e6331ad56414f9072506a77f8c6faf551eac7471b00389d01"),
                output: vec![148, 252, 136, 28, 159, 241, 218, 80, 210, 53, 237, 40, 242, 187, 207, 221, 254, 183, 8, 78, 99, 235, 213, 189, 17, 13, 58, 0, 0, 0, 0, 0],
                output_str: "00000000003a0d11bdd5eb634e08b7feddcfbbf228ed35d250daf19f1c88fc94",
            },
            Test {
                input: hex!("02000000a72c8a177f523946f42f22c3e86b8023221b4105e8007e59e81f6beb013e29aaf635295cb9ac966213fb56e046dc71df5b3f7f67ceaeab24038e743f883aff1aaafaf551eac7471b0166249b"),
                output: vec![129, 202, 168, 20, 81, 221, 248, 101, 156, 242, 175, 216, 89, 157, 45, 108, 138, 114, 68, 50, 225, 136, 242, 149, 248, 64, 11, 0, 0, 0, 0, 0],
                output_str: "00000000000b40f895f288e13244728a6c2d9d59d8aff29c65f8dd5114a8ca81",
            },
            Test {
                input: hex!("010000007824bc3a8a1b4628485eee3024abd8626721f7f870f8ad4d2f33a27155167f6a4009d1285049603888fe85a84b6c803a53305a8d497965a5e896e1a00568359589faf551eac7471b0065434e"),
                output: vec![254, 5, 225, 151, 24, 24, 134, 106, 220, 126, 142, 110, 47, 215, 232, 216, 153, 30, 3, 35, 73, 205, 145, 88, 0, 7, 48, 0, 0, 0, 0, 0],
                output_str: "00000000003007005891cd4923031e99d8e8d72f6e8e7edc6a86181897e105fe",
            },
            Test {
                input: hex!("0200000050bfd4e4a307a8cb6ef4aef69abc5c0f2d579648bd80d7733e1ccc3fbc90ed664a7f74006cb11bde87785f229ecd366c2d4e44432832580e0608c579e4cb76f383f7f551eac7471b00c36982"),
                output: vec![140, 236, 0, 56, 77, 114, 199, 231, 79, 91, 52, 13, 115, 175, 2, 250, 71, 203, 12, 19, 199, 175, 164, 38, 180, 240, 24, 0, 0, 0, 0, 0],
                output_str: "000000000018f0b426a4afc7130ccb47fa02af730d345b4fe7c7724d3800ec8c",
            },
        ];

        for test in tests {
            let header: Header =
                deserialize(&test.input).expect("Can't deserialize correct block header");
            assert_eq!(header.block_hash_with_scrypt().to_string(), test.output_str);
            assert_eq!(serialize(&header.block_hash_with_scrypt()), test.output);
        }
    }

    #[test]
    fn max_target_from_compact() {
        // The highest possible target in Dogecoin is defined as 0x1e0fffff
        let bits = 0x1e0fffff_u32;
        let want = Target::MAX_ATTAINABLE_MAINNET_DOGE;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want)
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment() {
        let height = 240;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1e0ffff0); // Genesis compact target on Mainnet
        let start_time: i64 = 1386325540; // Genesis block unix time
        let end_time: i64 = 1386475638; // Block 239 unix time
        let timespan = end_time - start_time; // Slower than expected (150,098 seconds diff)
        let adjustment = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment() {
        let height = 480;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target
        let start_time: i64 = 1386475638; // Block 239 unix time
        let end_time: i64 = 1386475840; // Block 479 unix time
        let timespan = end_time - start_time; // Faster than expected (202 seconds diff)
        let adjustment = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e00ffff); // Block 480 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment_using_headers() {
        use crate::{block::Version, dogecoin::constants::genesis_block, TxMerkleNode};
        use hashes::Hash;

        let height = 240;
        let params = Params::new(Network::Dogecoin);
        let epoch_start = genesis_block(&params).header;
        // Block 239, the only information used are `bits` and `time`
        let current = Header::new_from_pure_header( PureHeader{
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475638,
            bits: epoch_start.bits,
            nonce: epoch_start.nonce
        });
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment_using_headers() {
        use crate::{block::Version, TxMerkleNode};
        use hashes::Hash;

        let height = 480;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 479 compact target
        // Block 239, the only information used is `time`
        let epoch_start = Header::new_from_pure_header( PureHeader{
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475638,
            bits: starting_bits,
            nonce: 0
        });
        // Block 479, the only information used are `bits` and `time`
        let current = Header::new_from_pure_header( PureHeader{
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475840,
            bits: starting_bits,
            nonce: 0
        });
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e00ffff); // Block 480 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment() {
        let params = Params::new(Network::Dogecoin);
        let heights = vec![5000, 10000, 15000];
        let starting_bits = CompactTarget::from_consensus(21403001); // Arbitrary difficulty
        let timespan = (0.06 * params.pow_target_timespan as f64) as i64; // > 16x Faster than expected
        for height in heights {
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .min_transition_threshold_dogecoin(height)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn compact_target_from_minimum_downward_difficulty_adjustment() {
        let params = Params::new(Network::Dogecoin);
        let heights = vec![5000, 10000, 15000];
        let starting_bits = CompactTarget::from_consensus(21403001); // Arbitrary difficulty
        let timespan =  5 * params.pow_target_timespan; // > 4x Slower than expected
        for height in heights {
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .max_transition_threshold_dogecoin(&params)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn compact_target_from_adjustment_is_max_target() {
        let height = 480;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target (max target)
        let timespan =  4 * params.pow_target_timespan; // 4x Slower than expected
        let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
        let want = params.max_attainable_target.to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1e0f_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus(), consensus);
    }

    mod auxpow_tests {
        use super::*;
        use crate::{TxIn, TxOut, ScriptBuf, Witness};
        use hashes::Hash;

        const PARENT_BLOCK_CHAIN_ID: i32 = 42;
        const AUXPOW_BLOCK_CHAIN_ID: i32 = 98;
        const BASE_VERSION: i32 = 0x00000005;
        const NONCE: u32 = 7;
        const MERKLE_HEIGHT: usize = 30;

        /// Helper to create a dummy blockchain branch
        fn build_blockchain_merkle_branch(merkle_height: usize) -> Vec<TxMerkleNode>{
            (0..merkle_height)
                .map(|i| TxMerkleNode::from_byte_array([i as u8; 32]))
                .collect()
        }

        /// Helper to create a minimal coinbase transaction with the given script
        fn coinbase_from_script(script: ScriptBuf) -> Transaction {
            Transaction {
                version: crate::transaction::Version::ONE,
                lock_time: crate::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: crate::OutPoint::null(),
                    script_sig: script,
                    sequence: crate::Sequence::MAX,
                    witness: Witness::default(),
                }],
                output: vec![TxOut {
                    value: crate::Amount::from_sat(5000000000),
                    script_pubkey: ScriptBuf::new(),
                }],
            }
        }

        fn build_auxpow_coinbase_script(with_header: bool,
                                        blockchain_merkle_root: &[u8; 32],
                                        merkle_height: usize,
                                        nonce: u32) -> ScriptBuf {
            let mut data = Vec::new();

            if with_header {
                data.extend_from_slice(&MERGED_MINING_HEADER);
            }

            data.extend_from_slice(blockchain_merkle_root);

            let size = 1u32 << merkle_height;
            data.extend_from_slice(&size.to_le_bytes()); // TODO: check if this should be little endian
            data.extend_from_slice(&nonce.to_le_bytes()); // TODO: check if this should be little endian

            let mut script_data = vec![0x01, 0x02]; // Some prefix data
            script_data.extend_from_slice(&data);

            ScriptBuf::from_bytes(script_data)
        }

        /// Helper to create AuxPow coinbase transaction
        fn build_auxpow_coinbase(
            with_header: bool,
            blockchain_merkle_root: &[u8; 32],
            merkle_height: usize,
            nonce: u32,
        ) -> Transaction {
            let script = build_auxpow_coinbase_script(with_header,
                                                      blockchain_merkle_root,
                                                      merkle_height,
                                                      nonce);

            coinbase_from_script(script)
        }

        /// Helper to assemble an AuxPow struct from a coinbase transaction, expected index, and blockchain branch
        fn assemble_auxpow(
            coinbase_tx: Transaction,
            expected_index: i32,
            blockchain_branch: Vec<TxMerkleNode>,
        ) -> AuxPow {
            // Create parent block header
            let parent_block_header = PureHeader {
                version: Version::from_consensus(BASE_VERSION | (PARENT_BLOCK_CHAIN_ID << 16)),
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array(coinbase_tx.compute_txid().to_byte_array()),
                time: 0,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 0,
            };
            
            AuxPow {
                coinbase_tx,
                parent_hash: BlockHash::from_byte_array([2; 32]), // This is not checked
                coinbase_branch: vec![], // There is only a coinbase transaction in the block
                coinbase_index: 0,
                blockchain_branch,
                blockchain_index: expected_index,
                parent_block_header,
            }
        }

        /// Helper to create a valid AuxPow
        fn build_auxpow(aux_block_hash: BlockHash, chain_id: i32, merkle_height: usize, nonce: u32, with_header: bool) -> AuxPow {
            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);

            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);

            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let coinbase_tx = build_auxpow_coinbase(with_header, &blockchain_merkle_root.to_byte_array(), merkle_height, nonce);

            assemble_auxpow(coinbase_tx, expected_index, blockchain_branch)
        }

        #[test]
        fn test_valid_auxpow_modern_format() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);
            
            assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());
        }

        #[test]
        fn test_valid_auxpow_legacy_format() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, false);

            assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());
        }

        #[test]
        fn test_auxpow_not_from_coinbase() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let mut auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);
            auxpow.coinbase_index = 1; // Not coinbase
            
            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowValidationError::AuxPowNotFromCoinbase)
            );
        }

        #[test]
        fn test_parent_has_same_chain_id() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let mut auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);

            // Set parent block to have same chain ID
            auxpow.parent_block_header.version = Version::from_consensus(BASE_VERSION | (AUXPOW_BLOCK_CHAIN_ID << 16));

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowValidationError::ParentHasSameChainId)
            );
            
            assert!(auxpow.check(aux_block_hash, chain_id, false).is_ok());
        }

        #[test]
        fn test_chain_merkle_branch_too_long() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = 31; // Too long (>30)
            let nonce = NONCE;

            let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);
            
            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowValidationError::ChainMerkleBranchTooLong)
            );
        }

        #[test]
        fn test_invalid_coinbase_merkle_proof() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let mut auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);
            
            // Tamper with parent block merkle root
            auxpow.parent_block_header.merkle_root = TxMerkleNode::from_byte_array([0xff; 32]);
            
            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowValidationError::InvalidCoinbaseMerkleProof)
            );
        }

        #[test]
        fn test_coinbase_has_no_inputs() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);

            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);
            let mut coinbase_tx = build_auxpow_coinbase(true, &blockchain_merkle_root.to_byte_array(), merkle_height, nonce);

            coinbase_tx.input.clear(); // Remove inputs

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowValidationError::CoinbaseHasNoInputs)
            );
        }

        #[test]
        fn test_modified_aux_block_hash() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let modified_hash = BlockHash::from_byte_array([0x13; 32]); // Modified
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);

            assert_eq!(auxpow.check(modified_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot.into()));
        }

        #[test]
        fn test_wrong_chain_id() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let wrong_chain_id = AUXPOW_BLOCK_CHAIN_ID + 1;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);

            assert_eq!(auxpow.check(aux_block_hash, wrong_chain_id, true), Err(AuxPowCoinbaseScriptValidationError::InvalidChainIndex.into()));
        }

        #[test]
        fn test_missing_blockchain_merkle_root() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);

            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let wrong_blockchain_merkle_root = [0; 32];
            let coinbase_tx = build_auxpow_coinbase(true, &wrong_blockchain_merkle_root, merkle_height, nonce);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot.into())
            );
        }

        #[test]
        fn test_multiple_headers() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index).to_byte_array();
            let wrong_blockchain_merkle_root = [0; 32];

            // Two blockchain merkle roots with no headers (legacy)
            // Correct blockchain merkle root first
            let script_begin = build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(false, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());

            // Wrong blockchain merkle root first
            let script_begin = build_auxpow_coinbase_script(false, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert_eq!(auxpow.check(aux_block_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::LegacyRootTooFar.into()));

            // Merged mining header present with wrong blockchain merkle root following it
            let script_begin = build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert_eq!(auxpow.check(aux_block_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent.into()));

            let script_begin = build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert_eq!(auxpow.check(aux_block_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent.into()));

            // Multiple headers in coinbase is rejected
            let script_begin = build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert_eq!(auxpow.check(aux_block_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::MultipleHeaders.into()));

            let script_begin = build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert_eq!(auxpow.check(aux_block_hash, chain_id, true), Err(AuxPowCoinbaseScriptValidationError::MultipleHeaders.into()));

            // Correct blockchain merkle root after merged mining header is accepted
            let script_begin = build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(false, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());

            let script_begin = build_auxpow_coinbase_script(false, &wrong_blockchain_merkle_root, merkle_height, nonce);
            let script_end = build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
            let script = ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
            let coinbase_tx = coinbase_from_script(script);
            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
            assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());
        }

        #[test]
        fn test_header_not_adjacent() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let mut script_data = vec![0x01, 0x02];
            script_data.extend_from_slice(&MERGED_MINING_HEADER);
            script_data.push(0xff); // Extra byte between header and merkle root
            script_data.extend_from_slice(&blockchain_merkle_root.to_byte_array());
            script_data.extend_from_slice(&(1u32 << merkle_height).to_le_bytes());
            script_data.extend_from_slice(&nonce.to_le_bytes());

            let script = ScriptBuf::from_bytes(script_data);
            let coinbase_tx = coinbase_from_script(script);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent.into())
            );
        }

        #[test]
        fn test_legacy_root_too_far() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            // Create legacy format with merkle root too far from start
            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let mut script_data = vec![0; 25]; // 25 bytes prefix (>20, too far)
            script_data.extend_from_slice(&blockchain_merkle_root.to_byte_array());
            script_data.extend_from_slice(&(1u32 << merkle_height).to_le_bytes());
            script_data.extend_from_slice(&nonce.to_le_bytes());

            let script = ScriptBuf::from_bytes(script_data);
            let coinbase_tx = coinbase_from_script(script);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::LegacyRootTooFar.into())
            );
        }

        #[test]
        fn test_missing_merkle_size_and_nonce() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let script = build_auxpow_coinbase_script(true, &blockchain_merkle_root.to_byte_array(), merkle_height, nonce);
            let mut script_bytes = script.into_bytes();
            script_bytes.truncate(script_bytes.len() - 8); // Remove last 8 bytes (size + nonce)
            let coinbase_tx = coinbase_from_script(ScriptBuf::from_bytes(script_bytes));

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::MissingMerkleSizeAndNonce.into())
            );
        }

        #[test]
        fn test_merkle_size_mismatch() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let script = build_auxpow_coinbase_script(true, &blockchain_merkle_root.to_byte_array(), merkle_height - 1, nonce);
            let coinbase_tx = coinbase_from_script(script);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::MerkleSizeMismatch.into())
            );
        }

        #[test]
        fn test_incorrect_nonce_in_coinbase() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

            let script = build_auxpow_coinbase_script(true, &blockchain_merkle_root.to_byte_array(), merkle_height, nonce + 3);
            let coinbase_tx = coinbase_from_script(script);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::InvalidChainIndex.into())
            );
        }

        #[test]
        fn test_invalid_chain_index() {
            let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
            let chain_id = AUXPOW_BLOCK_CHAIN_ID;
            let merkle_height = MERKLE_HEIGHT;
            let nonce = NONCE;

            let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
            let blockchain_branch = build_blockchain_merkle_branch(merkle_height);

            let blockchain_merkle_root = AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index + 1);

            let coinbase_tx = build_auxpow_coinbase(true, &blockchain_merkle_root.to_byte_array(), merkle_height, nonce);

            let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

            assert_eq!(
                auxpow.check(aux_block_hash, chain_id, true),
                Err(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot.into())
            );
        }
    }
}
