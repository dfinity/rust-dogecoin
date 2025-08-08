// SPDX-License-Identifier: Apache-2.0

//! Dogecoin module.
//!
//! This module provides support for de/serialization, parsing and execution on data structures and
//! network messages related to Dogecoin.

pub mod address;
pub mod constants;
pub mod params;
pub mod auxpow;

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
use core::ops::{Deref, DerefMut};
use crate::dogecoin::auxpow::{AuxPow, VERSION_AUXPOW};

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

impl From<PureHeader> for Header {
    fn from(pure_header: PureHeader) -> Self {
        Self { pure_header, aux_pow: None }
    }
}

impl Decodable for Header {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let pure_header: PureHeader = Decodable::consensus_decode_from_finite_reader(r)?;
        let aux_pow = if pure_header.has_auxpow() {
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

impl PureHeader {
    /// Checks if a block header indicates it was merged mined and contains AuxPow information.
    pub fn has_auxpow(&self) -> bool {
        (self.version.to_consensus() & VERSION_AUXPOW) != 0
    }

    /// Extracts the chain ID from the block header's version field.
    pub fn extract_chain_id(&self) -> i32 {
        self.version.to_consensus() >> 16
    }

    /// Determines if a block header represents a legacy (pre-AuxPoW) block.
    pub fn is_legacy(&self) -> bool {
        self.version == Version::ONE
            // Random v2 block with no AuxPoW, treat as legacy
            || (self.version == Version::TWO && self.extract_chain_id() == 0)
    }

    /// Extracts the base version number from a block header, removing AuxPoW and chain ID bits.
    pub fn extract_base_version(&self) -> i32 {
        self.version.to_consensus() % VERSION_AUXPOW
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
    use hex::{test_hex_unwrap as hex};
    use hashes::Hash;
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
        let header = &some_block[0..80];

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
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1388017789);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(469798878));
        assert_eq!(real_decode.header.nonce, 1015863808);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow_with_scrypt(real_decode.header.target()).unwrap(),
            real_decode.block_hash_with_scrypt()
        );
        // Bitcoin network is used because Dogecoin's difficulty calculation is based on Bitcoin's,
        // which uses Bitcoin's `max_attainable_target` value
        assert_eq!(real_decode.header.difficulty(BitcoinNetwork::Bitcoin), 455);
        assert_eq!(real_decode.header.difficulty_float(), 455.52430084170516);

        assert!(!real_decode.header.has_auxpow());
        assert_eq!(real_decode.header.extract_chain_id(), 0);
        assert_eq!(real_decode.header.extract_base_version(), 1);
        assert!(real_decode.header.is_legacy());

        assert!(real_decode.header.aux_pow.is_none());

        assert_eq!(serialize(&real_decode.header.pure_header), header);
        assert_eq!(serialize(&real_decode.header), header);
        assert_eq!(serialize(&real_decode), some_block);
    }

    #[test]
    fn dogecoin_block_test_with_auxpow() {
        // Mainnet Dogecoin block d3ea48350b102b90acf9eac6629072d5f697c02faf360b26d365e7b2bfb98070
        let block = hex!("020162001e21ad14bc1ef20cf2d58e2b755ae4a7bfb75c906c74ef3dbb97cc57dcd77581b14423c43517df2b4f3277731daba29d0d865b515a6f19f5fb61d5799b28f2c9b48713540fa8071b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4f032ac209fabe6d6dd3ea48350b102b90acf9eac6629072d5f697c02faf360b26d365e7b2bfb980700100000000000000062f503253482f04ce871354080811312915000000092f7374726174756d2f000000000100f2052a010000001976a914f332ec6f1729495e7edcd8ce9d887742567fe60988ac0000000006d2bbd93141ea6d2c8434caeb01828a2a522275b66d2b21fe4ed8230cfe65a101ad2f07c348abdc05f57e2e7d8763488aad71df9f557aec46ae0207ae2bb74a1500000000000000000002000000f288b555ed9b44c814afbbbac135d95e0984a5cc7cb554fccbd2ca27c5e423cebf3021ed058ac83eaa0f64b0d405fc99216209b7e56deeeefceb3629210d1cabcb8713545a50021bc40227b50301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d0300b1050101062f503253482fffffffff010085fd36af050000232102c9cbaeb767cc8c884204601f322c6977890cdd3d274f8b1a704ae00382102191ac0000000001000000011fcccc77028fc5fb96d60ee5f258da271ba9b4fdec12594a5dd2efa1fb5bd14b010000006b483045022100f4a17664176706f74877433dbfb8e68a5c1e45730da9248a8da3bab833cea1ca022018fee77621c20f196b82c3c8fd663959b0c8ea985b0407bdbac1414a5a5a21bf0121033fcc1cb9c1b7b11758eb2cd3a25b4ff917a5e248f5d6fcc74160dd6a450acf8bffffffff020759dd6e000000001976a914a553c686ac1aa534ffcb3b694c463944175a6f3c88ac8548f276890700001976a914a1ea13863020f36897b671ad328d98e9364f12b488ac000000000100000001215c45fc31d3beae4a5c76efbb0925d0b4bace72f62248aa3777927eecb42152000000006b483045022100bd3f18da6acd8180ed99c7c7fc6feab18653008cc58be5c32a470193aea330860220719c64121805606240c48dab2e8e3f3d82501b78b78597043ca134abf4c85443012103e6435d9ad2a3f3ff2d2c58aef41075df4eb5417c313d3ea4d5bb87ab46241940ffffffff0140ab8aac140000001976a91481db1aa49ebc6a71cad96949eb28e22af85eb0bd88ac00000000");
        let header = &block[0..398];
        let pure_header = &header[0..80];
        let auxpow = &header[80..];
        let auxpow_coinbase_tx = &auxpow[..164];
        let auxpow_parent_hash = &auxpow[164..196];
        let auxpow_coinbase_branch = &auxpow[196..229];
        let auxpow_coinbase_index = &auxpow[229..233];
        let auxpow_blockchain_branch = &auxpow[233..234];
        let auxpow_blockchain_index = &auxpow[234..238];
        let auxpow_parent_block_header = &auxpow[238..];

        let currhash = hex!("7080b9bfb2e765d3260b36af2fc097f6d5729062c6eaf9ac902b100b3548ead3");
        let prevhash = hex!("1e21ad14bc1ef20cf2d58e2b755ae4a7bfb75c906c74ef3dbb97cc57dcd77581");
        let merkle = hex!("b14423c43517df2b4f3277731daba29d0d865b515a6f19f5fb61d5799b28f2c9");

        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let block_decode = decode.unwrap();

        assert_eq!(serialize(&block_decode.header.block_hash()), currhash);
        assert_eq!(block_decode.header.version, Version::from_consensus(6422786));
        assert_eq!(serialize(&block_decode.header.prev_blockhash), prevhash);
        assert_eq!(block_decode.header.merkle_root, block_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&block_decode.header.merkle_root), merkle);
        assert_eq!(block_decode.header.time, 1410566068);
        assert_eq!(block_decode.header.bits, CompactTarget::from_consensus(453486607));
        assert_eq!(block_decode.header.nonce, 0);

        // Should fail because AuxPow is used
        assert_eq!(
            block_decode.header.validate_pow_with_scrypt(block_decode.header.target()),
            Err(ValidationError::BadProofOfWork)
        );
        // Bitcoin network is used because Dogecoin's difficulty calculation is based on Bitcoin's,
        // which uses Bitcoin's `max_attainable_target` value
        assert_eq!(block_decode.header.difficulty(BitcoinNetwork::Bitcoin), 8559);
        assert_eq!(block_decode.header.difficulty_float(), 8559.417587564147);

        assert!(block_decode.header.has_auxpow());
        assert_eq!(block_decode.header.extract_chain_id(), 98);
        assert_eq!(block_decode.header.extract_base_version(), 2);
        assert!(!block_decode.header.is_legacy());

        assert!(block_decode.header.aux_pow.is_some());
        let auxpow_decode = block_decode.header.aux_pow.as_ref().unwrap();
        assert_eq!(serialize(&auxpow_decode.coinbase_tx), auxpow_coinbase_tx);
        assert_eq!(auxpow_decode.parent_hash.to_byte_array(), auxpow_parent_hash);
        assert_eq!(serialize(&auxpow_decode.coinbase_branch), auxpow_coinbase_branch);
        assert_eq!(auxpow_decode.coinbase_index.to_le_bytes(), auxpow_coinbase_index);
        assert_eq!(serialize(&auxpow_decode.blockchain_branch), auxpow_blockchain_branch);
        assert_eq!(auxpow_decode.blockchain_index.to_le_bytes(), auxpow_blockchain_index);
        assert_eq!(serialize(&auxpow_decode.parent_block_header), auxpow_parent_block_header);

        assert_eq!(serialize(&auxpow_decode), auxpow);
        assert_eq!(serialize(&block_decode.header.pure_header), pure_header);
        assert_eq!(serialize(&block_decode.header), header);
        assert_eq!(serialize(&block_decode), block);
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
    fn compact_target_from_downards_difficulty_adjustment_digishield() {
        let height = 1531886;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1b01c45a); // Block 1_531_885 compact target
        let start_time: i64 = 1483302792; // Block 1_531_884 unix time
        let end_time: i64 = 1483302869; // Block 1_531_885 unix time
        let timespan = end_time - start_time; // Slower than expected (77 seconds diff)
        let adjustment = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1b01d36e); // Block 1_531_886 compact target
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
    fn compact_target_from_upwards_difficulty_adjustment_digishield() {
        let height = 1531882;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1b01dc29); // Block 1_531_881 compact target
        let start_time: i64 = 1483302572; // Block 1_531_880 unix time
        let end_time: i64 = 1483302608; // Block 1_531_881 unix time
        let timespan = end_time - start_time; // Faster than expected (36 seconds diff)
        let adjustment = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1b01c45a); // Block 1_531_882 compact target
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
        let current = PureHeader {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475638,
            bits: epoch_start.bits,
            nonce: epoch_start.nonce
        }.into();
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment_using_headers_digishield() {
        use crate::{block::Version, TxMerkleNode};
        use std::str::FromStr;

        let height = 1_131_290;
        let params = Params::new(Network::Dogecoin);
        // Block 1_131_288, the only information used is `time`
        let epoch_start = PureHeader {
            version: Version::from_consensus(6422787),
            prev_blockhash: BlockHash::from_str("ac0ffad025605732b310be7edf52111fa9511ffc54f06d21aab1c50d4085b39f").expect("failed to parse block hash"),
            merkle_root: TxMerkleNode::from_str("80c67973ef43f2df8a3641dac7da16ea59f55e4d77b9206c6e5cfa25d3bf094b").expect("failed to parse merkle root"),
            time: 1458248044,
            bits: CompactTarget::from_consensus(0x1b01e7c1),
            nonce: 0
        }.into();
        // Block 1_131_289, the only information used are `bits` and `time`
        let current = PureHeader {
            version: Version::from_consensus(6422787),
            prev_blockhash: BlockHash::from_str("7724f7b3f9652ebc121ce101a10bfabd6815518b2814bd16f7a2dcc13dd121ec").expect("failed to parse block hash"),
            merkle_root: TxMerkleNode::from_str("33c13df68d2f74c76367659cc95436510ed5504ef3c53ae90679ec12ab4e8b81").expect("failed to parse merkle root"),
            time: 1458248269,
            bits: CompactTarget::from_consensus(0x1b01cf5d),
            nonce: 0
        }.into();
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1b0269d1); // Block 1_131_290 compact target
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
        let epoch_start = PureHeader{
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475638,
            bits: starting_bits,
            nonce: 0
        }.into();
        // Block 479, the only information used are `bits` and `time`
        let current = PureHeader{
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1386475840,
            bits: starting_bits,
            nonce: 0
        }.into();
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1e00ffff); // Block 480 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment_using_headers_digishield() {
        use crate::{block::Version, TxMerkleNode};
        use std::str::FromStr;

        let height = 1_131_286;
        let params = Params::new(Network::Dogecoin);
        // Block 1_131_284, the only information used is `time`
        let epoch_start = PureHeader {
            version: Version::from_consensus(6422787),
            prev_blockhash: BlockHash::from_str("a695a2cc43bd5c5f32acecada764b8764b044f067909b997d4f98a6733c3fa70").expect("failed to parse block hash"),
            merkle_root: TxMerkleNode::from_str("806736d9e0cab2de97e7afc9f2031c5a0413c0bff00d82cc38fa0d568d2f7135").expect("failed to parse merkle root"),
            time: 1458247987,
            bits: CompactTarget::from_consensus(0x1b02f5b6),
            nonce: 0
        }.into();
        // Block 1_131_285, the only information used are `bits` and `time`
        let current = PureHeader {
            version: Version::from_consensus(6422787),
            prev_blockhash: BlockHash::from_str("db185a7d97060e13dd53ff759f9280d473d7bb6fccc8883fbc8f1fa1f071fc82").expect("failed to parse block hash"),
            merkle_root: TxMerkleNode::from_str("20419a4d74c0284e241ca5d3c91ea2b533d8a6502e4b6e4a7f8a2fc50d42796e").expect("failed to parse merkle root"),
            time: 1458247995,
            bits: CompactTarget::from_consensus(0x1b029d4f),
            nonce: 0
        }.into();
        let adjustment = CompactTarget::from_header_difficulty_adjustment_dogecoin(epoch_start, current, params, height);
        let adjustment_bits = CompactTarget::from_consensus(0x1b025a60); // Block 1_131_286 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment() {
        let pre_digishield_heights = vec![5_000, 10_000, 15_000];
        let digishield_heights = vec![145_000, 1_000_000];
        let starting_bits = CompactTarget::from_consensus(0x1b025a60); // Arbitrary difficulty
        let params = Params::new(Network::Dogecoin);
        for height in pre_digishield_heights {
            let timespan = (0.06 * params.pow_target_timespan(height) as f64) as i64; // > 16x Faster than expected
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .min_transition_threshold_dogecoin(&params, height)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
        for height in digishield_heights {
            let timespan = -params.pow_target_timespan(height); // Negative timespan
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .min_transition_threshold_dogecoin(&params, height)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn compact_target_from_minimum_downward_difficulty_adjustment() {
        let pre_digishield_heights = vec![5_000, 10_000, 15_000];
        let digishield_heights = vec![145_000, 1_000_000];
        let starting_bits = CompactTarget::from_consensus(0x1b02f5b6); // Arbitrary difficulty
        let params = Params::new(Network::Dogecoin);
        for height in pre_digishield_heights {
            let timespan =  4 * params.pow_target_timespan(height); // 4x Slower than expected
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .max_transition_threshold_dogecoin(&params, height)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
        for height in digishield_heights {
            let timespan = 5 * params.pow_target_timespan(height); // 5x Slower than expected
            let got = CompactTarget::from_next_work_required_dogecoin(starting_bits, timespan, &params, height);
            let want = Target::from_compact(starting_bits)
                .max_transition_threshold_dogecoin(&params, height)
                .to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn compact_target_from_adjustment_is_max_target() {
        let height = 480;
        let params = Params::new(Network::Dogecoin);
        let starting_bits = CompactTarget::from_consensus(0x1e0fffff); // Block 240 compact target (max target)
        let timespan =  4 * params.pow_target_timespan(height); // 4x Slower than expected
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
}
