// SPDX-License-Identifier: Apache-2.0

//! Dogecoin AuxPow validation.
//!
//! This module provides functionality for validating Auxiliary Proof-of-Work (AuxPoW)
//! blocks used in Dogecoin's merged mining.

use core::fmt;

use hashes::Hash;

use crate::consensus::Encodable;
use crate::dogecoin::get_chain_id;
use crate::internal_macros::impl_consensus_encoding;
use crate::prelude::*;
use crate::{BlockHash, Transaction, TxMerkleNode};

/// AuxPow version bit, see <https://github.com/dogecoin/dogecoin/blob/d7cc7f8bbb5f790942d0ed0617f62447e7675233/src/primitives/pureheader.h#L23>
pub const VERSION_AUXPOW: i32 = 1 << 8;
/// Merged mining header, see <https://github.com/dogecoin/dogecoin/blob/bc8cca48968dfa3f60b5eae6a2b92bdd2870eee3/src/auxpow.h#L24>
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
    InvalidAuxPowCoinbaseScript(AuxPowCoinbaseScriptValidationError),
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
            AuxPowValidationError::InvalidAuxPowCoinbaseScript(err) => write!(f, "{}", err),
        }
    }
}

/// AuxPow coinbase script validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxPowCoinbaseScriptValidationError {
    /// Missing blockchain merkle root in the coinbase transaction
    MissingMerkleRoot,
    /// Multiple merged mining headers in the coinbase transaction
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
    InvalidChainIndex,
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

impl From<AuxPowCoinbaseScriptValidationError> for AuxPowValidationError {
    fn from(err: AuxPowCoinbaseScriptValidationError) -> Self {
        AuxPowValidationError::InvalidAuxPowCoinbaseScript(err)
    }
}

/// Data for merged-mining AuxPow.
///
/// It contains the parent block's coinbase tx that can be verified to be in the parent block.
/// The coinbase transaction's input contains the hash of the auxiliary (merged-mined) block header.
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
    /// The index of the coinbase tx in the parent block's Merkle tree. Must be 0.
    pub coinbase_index: i32,
    /// The Merkle branch linking the auxiliary block header to the blockchain Merkle root present
    /// in the coinbase tx.
    pub blockchain_branch: Vec<TxMerkleNode>,
    /// The index of the auxiliary block header in the Merkle tree.
    pub blockchain_index: i32,
    /// Parent block header on which the PoW is done.
    pub parent_block_header: crate::blockdata::block::Header,
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

    /// Computes the merkle root from a child hash and its merkle branch proof.
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
    /// * `script` - The coinbase transaction input script containing the merged mining data
    /// * `blockchain_merkle_root` - The merkle root of the headers of the merged-mined blockchains
    /// * `chain_id` - Chain ID of the blockchain used for deterministic index calculation
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validations pass, or an `AuxPowValidationError` describing the failure
    ///
    /// # Merged Mining Protocol
    ///
    /// The coinbase script embeds merged mining data in this format:
    /// ```text
    /// [...prefix] [merged_mining_header] [blockchain_merkle_root] [merkle_size] [merkle_nonce] [suffix...]
    /// ```
    /// Where:
    /// - `merged_mining_header`: 4-byte magic header (0xfabe6d6d)
    /// - `blockchain_merkle_root`: 32-byte root of the blockchain merkle tree
    /// - `merkle_size`: 4-byte little-endian merkle tree size (2^height)
    /// - `merkle_nonce`: 4-byte little-endian nonce to calculate deterministic slot of headers into merkle tree
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
                // Check that the header immediately precedes blockchain merkle root
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

        let size_bytes =
            [remaining_script[0], remaining_script[1], remaining_script[2], remaining_script[3]];
        let size = u32::from_le_bytes(size_bytes);

        let merkle_height = self.blockchain_branch.len();
        if size != (1u32 << merkle_height) {
            return Err(AuxPowCoinbaseScriptValidationError::MerkleSizeMismatch);
        }

        let nonce_bytes =
            [remaining_script[4], remaining_script[5], remaining_script[6], remaining_script[7]];
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
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    /// Calculates the expected index of the AuxPow block header in the blockchain merkle tree.
    ///
    /// Given the merkle tree size, nonce, and chain ID, computes a pseudo-random slot in the blockchain
    /// merkle tree. This prevents replay attacks in merged mining by assigning each merged-mined
    /// block header a deterministic position in the blockchain merkle tree.
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

    /// Validates the AuxPow structure for merged mining.
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
    pub fn check(
        &self,
        aux_block_hash: BlockHash,
        chain_id: i32,
        strict_chain_id: bool,
    ) -> Result<(), AuxPowValidationError> {
        if self.coinbase_index != 0 {
            return Err(AuxPowValidationError::AuxPowNotFromCoinbase);
        }

        if strict_chain_id && get_chain_id(&self.parent_block_header) == chain_id {
            return Err(AuxPowValidationError::ParentHasSameChainId);
        }

        if self.blockchain_branch.len() > 30 {
            return Err(AuxPowValidationError::ChainMerkleBranchTooLong);
        }

        let blockchain_merkle_root = Self::compute_merkle_root(
            aux_block_hash,
            &self.blockchain_branch,
            self.blockchain_index,
        );

        let mut blockchain_merkle_root_le = blockchain_merkle_root.to_byte_array();
        blockchain_merkle_root_le.reverse();

        let coinbase_hash = self.coinbase_tx.compute_txid();
        let transactions_merkle_root = Self::compute_merkle_root(
            BlockHash::from_byte_array(coinbase_hash.to_byte_array()),
            &self.coinbase_branch,
            self.coinbase_index,
        );

        if transactions_merkle_root != self.parent_block_header.merkle_root {
            return Err(AuxPowValidationError::InvalidCoinbaseMerkleProof);
        }

        if self.coinbase_tx.input.is_empty() {
            return Err(AuxPowValidationError::CoinbaseHasNoInputs);
        }

        let script = &self.coinbase_tx.input[0].script_sig;

        self.check_merged_mining_coinbase_script(
            script.as_bytes(),
            &blockchain_merkle_root_le,
            chain_id,
        )
        .map_err(AuxPowValidationError::InvalidAuxPowCoinbaseScript)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hashes::Hash;

    use super::*;
    use crate::block::{Header as PureHeader, Version};
    use crate::consensus::encode::deserialize_hex;
    use crate::{CompactTarget, ScriptBuf, TxIn, TxOut, Txid, Witness};

    const PARENT_BLOCK_CHAIN_ID: i32 = 42;
    const AUXPOW_BLOCK_CHAIN_ID: i32 = 98;
    const BASE_VERSION: i32 = 0x00000005;
    const NONCE: u32 = 7;
    const MERKLE_HEIGHT: usize = 30;

    /// Helper to create a dummy blockchain branch
    fn build_blockchain_merkle_branch(merkle_height: usize) -> Vec<TxMerkleNode> {
        (0..merkle_height).map(|i| TxMerkleNode::from_byte_array([i as u8; 32])).collect()
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

    /// Helper to create an AuxPow coinbase transaction's script
    fn build_auxpow_coinbase_script(
        with_header: bool,
        blockchain_merkle_root: &[u8; 32],
        merkle_height: usize,
        nonce: u32,
    ) -> ScriptBuf {
        let mut data = Vec::new();

        if with_header {
            data.extend_from_slice(&MERGED_MINING_HEADER);
        }

        // Reverse endianness (big-endian → little-endian)
        let mut blockchain_merkle_root_le = *blockchain_merkle_root;
        blockchain_merkle_root_le.reverse();
        data.extend_from_slice(&blockchain_merkle_root_le);

        let size = 1u32 << merkle_height;
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());

        let mut script_data = vec![0x01, 0x02]; // Some prefix data
        script_data.extend_from_slice(&data);

        ScriptBuf::from_bytes(script_data)
    }

    /// Helper to create an AuxPow coinbase transaction
    fn build_auxpow_coinbase(
        with_header: bool,
        blockchain_merkle_root: &[u8; 32],
        merkle_height: usize,
        nonce: u32,
    ) -> Transaction {
        let script =
            build_auxpow_coinbase_script(with_header, blockchain_merkle_root, merkle_height, nonce);

        coinbase_from_script(script)
    }

    /// Helper to assemble an AuxPow struct from a coinbase transaction, expected index, and blockchain branch
    fn assemble_auxpow(
        coinbase_tx: Transaction,
        expected_index: i32,
        blockchain_branch: Vec<TxMerkleNode>,
    ) -> AuxPow {
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
            parent_hash: BlockHash::from_byte_array([2; 32]), // Dummy value (this is not checked at all)
            coinbase_branch: vec![], // There is only a coinbase transaction in the block
            coinbase_index: 0,
            blockchain_branch,
            blockchain_index: expected_index,
            parent_block_header,
        }
    }

    /// Helper to create a valid AuxPow
    fn build_auxpow(
        aux_block_hash: BlockHash,
        chain_id: i32,
        merkle_height: usize,
        nonce: u32,
        with_header: bool,
    ) -> AuxPow {
        let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);

        let blockchain_branch = build_blockchain_merkle_branch(merkle_height);

        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let coinbase_tx = build_auxpow_coinbase(
            with_header,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height,
            nonce,
        );

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
        auxpow.parent_block_header.version =
            Version::from_consensus(BASE_VERSION | (AUXPOW_BLOCK_CHAIN_ID << 16));

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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);
        let mut coinbase_tx = build_auxpow_coinbase(
            true,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height,
            nonce,
        );

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

        assert_eq!(
            auxpow.check(modified_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot.into())
        );
    }

    #[test]
    fn test_wrong_chain_id() {
        let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
        let chain_id = AUXPOW_BLOCK_CHAIN_ID;
        let wrong_chain_id = AUXPOW_BLOCK_CHAIN_ID + 1;
        let merkle_height = MERKLE_HEIGHT;
        let nonce = NONCE;

        let auxpow = build_auxpow(aux_block_hash, chain_id, merkle_height, nonce, true);

        assert_eq!(
            auxpow.check(aux_block_hash, wrong_chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::InvalidChainIndex.into())
        );
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
        let coinbase_tx =
            build_auxpow_coinbase(true, &wrong_blockchain_merkle_root, merkle_height, nonce);

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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index)
                .to_byte_array();
        let wrong_blockchain_merkle_root = [0; 32];

        // Legacy: Two blockchain merkle roots with no headers
        // Correct blockchain merkle root first
        let script_begin =
            build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
        let script_end = build_auxpow_coinbase_script(
            false,
            &wrong_blockchain_merkle_root,
            merkle_height,
            nonce,
        );
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());

        // Wrong blockchain merkle root first
        let script_begin = build_auxpow_coinbase_script(
            false,
            &wrong_blockchain_merkle_root,
            merkle_height,
            nonce,
        );
        let script_end =
            build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::LegacyRootTooFar.into())
        );

        // Merged mining header present with wrong blockchain merkle root following it
        let script_begin =
            build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
        let script_end =
            build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent.into())
        );

        let script_begin =
            build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
        let script_end =
            build_auxpow_coinbase_script(false, &blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::HeaderNotAdjacent.into())
        );

        // Multiple headers in coinbase gets rejected
        let script_begin =
            build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
        let script_end =
            build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::MultipleHeaders.into())
        );

        let script_begin =
            build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
        let script_end =
            build_auxpow_coinbase_script(true, &wrong_blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::MultipleHeaders.into())
        );

        // Correct blockchain merkle root after merged mining header is accepted
        let script_begin =
            build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
        let script_end = build_auxpow_coinbase_script(
            false,
            &wrong_blockchain_merkle_root,
            merkle_height,
            nonce,
        );
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
        let coinbase_tx = coinbase_from_script(script);
        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch.clone());
        assert!(auxpow.check(aux_block_hash, chain_id, true).is_ok());

        let script_begin = build_auxpow_coinbase_script(
            false,
            &wrong_blockchain_merkle_root,
            merkle_height,
            nonce,
        );
        let script_end =
            build_auxpow_coinbase_script(true, &blockchain_merkle_root, merkle_height, nonce);
        let script =
            ScriptBuf::from_bytes([script_begin.into_bytes(), script_end.into_bytes()].concat());
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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let mut script_data = vec![0x01, 0x02];
        script_data.extend_from_slice(&MERGED_MINING_HEADER);
        script_data.push(0xff); // Extra byte between header and merkle root
        let mut blockchain_merkle_root_le = blockchain_merkle_root.to_byte_array();
        blockchain_merkle_root_le.reverse();
        script_data.extend_from_slice(&blockchain_merkle_root_le);
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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let mut script_data = vec![0; 25]; // 25 bytes prefix (>20, too far)
        let mut blockchain_merkle_root_le = blockchain_merkle_root.to_byte_array();
        blockchain_merkle_root_le.reverse();
        script_data.extend_from_slice(&blockchain_merkle_root_le);
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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let script = build_auxpow_coinbase_script(
            true,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height,
            nonce,
        );
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
    fn test_incorrect_merkle_size_in_coinbase() {
        let aux_block_hash = BlockHash::from_byte_array([0x12; 32]);
        let chain_id = AUXPOW_BLOCK_CHAIN_ID;
        let merkle_height = MERKLE_HEIGHT;
        let nonce = NONCE;

        let expected_index = AuxPow::get_expected_index(nonce, chain_id, merkle_height);
        let blockchain_branch = build_blockchain_merkle_branch(merkle_height);
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let script = build_auxpow_coinbase_script(
            true,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height - 1,
            nonce,
        );
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
        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, expected_index);

        let script = build_auxpow_coinbase_script(
            true,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height,
            nonce + 3,
        );
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
        let wrong_index = expected_index + 1;

        let blockchain_branch = build_blockchain_merkle_branch(merkle_height);

        let blockchain_merkle_root =
            AuxPow::compute_merkle_root(aux_block_hash, &blockchain_branch, wrong_index);

        let coinbase_tx = build_auxpow_coinbase(
            true,
            &blockchain_merkle_root.to_byte_array(),
            merkle_height,
            nonce,
        );

        let auxpow = assemble_auxpow(coinbase_tx, expected_index, blockchain_branch);

        assert_eq!(
            auxpow.check(aux_block_hash, chain_id, true),
            Err(AuxPowCoinbaseScriptValidationError::MissingMerkleRoot.into())
        );
    }

    #[test]
    fn test_valid_auxpow_dogecoin_mainnet_single_merged_mined_chain() {
        // AuxPow information for Dogecoin mainnet block, height 2_679_506
        let coinbase_tx = deserialize_hex::<Transaction>("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d03119d1804ec4eb05c2f4254432e434f4d2f4c5443fabe6d6d283fa35edb604a913ead7e776b534f1661723da6721131eee75a39738ed2e8f8010000000000000001000a7de000000000000000ffffffff02fef83d95000000001976a91497b22b5ff0e6fd5e06c2592bdff0bfd677009f4788ac0000000000000000266a24aa21a9ed710de897f5217b49832c28a07a7f71c924d6c502efacbd3afdfe78565c9cc0d200000000").unwrap();
        let coinbase_tx_id =
            Txid::from_str("d7f98ad4f597cbd536529b35739d4ae8f13b788d0f6e9f4408c4b457410eed9c")
                .unwrap();

        assert_eq!(coinbase_tx.compute_txid(), coinbase_tx_id);
        assert_eq!(coinbase_tx.input.len(), 1);

        let coinbase_script = ScriptBuf::from_hex("03119d1804ec4eb05c2f4254432e434f4d2f4c5443fabe6d6d283fa35edb604a913ead7e776b534f1661723da6721131eee75a39738ed2e8f8010000000000000001000a7de000000000000000").unwrap();
        assert_eq!(coinbase_script, coinbase_tx.input.first().unwrap().script_sig);

        // Litecoin mainnet block, height 1_613_073
        let parent_block_header = deserialize_hex::<PureHeader>("000000208adac0c3312ce198ee1bc0b0ca079a648b47f7a2d36b92680a164e9f3472b681bb83e66a3c19332e7825a0e4e6e5bed63192d8c0bf1321803d06881cbd470f44ec4eb05c8075011a855549e5").unwrap();
        let parent_hash =
            BlockHash::from_str("5c87f7add34f31c644275476761e4273ec27c6bb31d383f27693df84f78a4275")
                .unwrap();

        assert_eq!(parent_block_header.block_hash(), parent_hash);

        let coinbase_branch = vec![
            TxMerkleNode::from_str(
                "6d8897d112189fdf9af120b70d16a26783ffda7a2f1968984fee9fb9e7764b79",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "37a820e558328ef2ec366c4e83e9e627cb34ced06a140423686b5ee6def33e89",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "f1369a82235d4c3a922444ae6764ee00efa9c040ea13c8ce2b83d2b1865cb5ae",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "3859ccd5dd341126af04fe193e021294cde59bcb06ebf9195c4406f96a98dd1a",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "37d8306e628ade2df4f868ce235ac0f4f5e32195664fdf865e43ed236299e81b",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "827e84f9933bd63ebab743610f2a94c2d8d1cf2e79d0879a27da359b06bee33d",
            )
            .unwrap(),
        ];

        let blockchain_branch = vec![];

        let valid_auxpow = AuxPow {
            coinbase_tx,
            parent_hash,
            coinbase_branch,
            coinbase_index: 0,
            blockchain_branch,
            blockchain_index: 0,
            parent_block_header,
        };

        let aux_block_hash =
            BlockHash::from_str("283fa35edb604a913ead7e776b534f1661723da6721131eee75a39738ed2e8f8")
                .unwrap();
        let chain_id = 98; // Dogecoin chain ID

        assert!(valid_auxpow.check(aux_block_hash, chain_id, true).is_ok());
    }

    #[test]
    fn test_valid_auxpow_dogecoin_mainnet_multiple_merged_mined_chains() {
        // AuxPow information for Dogecoin mainnet block, height 1_000_000
        let coinbase_tx = deserialize_hex::<Transaction>("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4c0350c90d047cbb6d5608028f23145c045200fabe6d6d5ae93eb8863161c9cd991ba9f7b0fa4353b645310b2edabb123066dea3c9150140000000000000000d2f6e6f64655374726174756d2f0000000001e81c0695000000001976a9145da2560b857f5ba7874de4a1173e67b4d509c46688ac00000000").unwrap();
        let coinbase_tx_id =
            Txid::from_str("02454219e64615c8a9aa813fb520a924a36229f5a658de069b5a4c588ffaa209")
                .unwrap();

        assert_eq!(coinbase_tx.compute_txid(), coinbase_tx_id);
        assert_eq!(coinbase_tx.input.len(), 1);

        let coinbase_script = ScriptBuf::from_hex("0350c90d047cbb6d5608028f23145c045200fabe6d6d5ae93eb8863161c9cd991ba9f7b0fa4353b645310b2edabb123066dea3c9150140000000000000000d2f6e6f64655374726174756d2f").unwrap();
        assert_eq!(coinbase_script, coinbase_tx.input.first().unwrap().script_sig);

        // Litecoin mainnet block, height 903_504
        let parent_block_header = deserialize_hex::<PureHeader>("03000000d37139870c8a6853cdbdb0eba43956efccedd7f50dcd57ca13187200da12320a6102f658ec72bd6b3550dd54d3b3c9e4b7063ec4662e94e768fb1cdda77e678cd4ba6d56f542011bb8a07866").unwrap();
        let parent_hash =
            BlockHash::from_str("3d6a5046000041f2517ca0d436b558640803cfa2596d1d2febfe6079d84eb358")
                .unwrap();

        assert_eq!(parent_block_header.block_hash(), parent_hash);

        let coinbase_branch = vec![
            TxMerkleNode::from_str(
                "e77d6288e0f8280ab954bcef89f5d7d524c8137f3929aa12f5e81f753032f936",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "8c104741e043384a401bd56e815b6c36f88457e9940958d1e5648cc51f71c889",
            )
            .unwrap(),
        ];

        let blockchain_branch = vec![
            TxMerkleNode::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "f98c4e9736d8eb8bb46299798906695c755369a3df99a93ffdded1713f1cf6e2",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "48e55233b9707330def98c80a2105eaa5fac8f687d872ffb4b4741fa2bdb247d",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "c77d206e2f3cc38e18b85aaa89a8f142a9bf0f4106925d39708f91083e7d8594",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "c98b626e977b43fffd7a2cdd179bd15dc8566b0c21252562f944f40ab5870ff7",
            )
            .unwrap(),
            TxMerkleNode::from_str(
                "4433bbe69867ef956764b17c57ccb89189c901709a8aa771ca119e1d8437912c",
            )
            .unwrap(),
        ];

        let valid_auxpow = AuxPow {
            coinbase_tx,
            parent_hash,
            coinbase_branch,
            coinbase_index: 0,
            blockchain_branch,
            blockchain_index: 56,
            parent_block_header,
        };

        let aux_block_hash =
            BlockHash::from_str("6aae55bea74235f0c80bd066349d4440c31f2d0f27d54265ecd484d8c1d11b47")
                .unwrap();
        let chain_id = 98; // Dogecoin chain ID

        assert!(valid_auxpow.check(aux_block_hash, chain_id, true).is_ok());
    }
}
