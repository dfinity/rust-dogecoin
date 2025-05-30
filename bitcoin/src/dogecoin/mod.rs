//! Dogecoin module.
//!
//! This module provides support for de/serialization, parsing and execution on data structures and
//! network messages related to Dogecoin.

mod constants;
pub mod params;

use crate::block::{Header, TxMerkleNode};
use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{Read, Write};
use crate::prelude::*;
use crate::{io, BlockHash, Transaction};

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

    /// Returns the block hash using the scrypt hash function.
    pub fn block_hash_with_scrypt(&self) -> BlockHash { self.header.block_hash_with_scrypt() }
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

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::block::{ValidationError, Version};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::{CompactTarget, Network, Target, Work};

    #[test]
    fn dogecoin_block_test() {
        let params = crate::consensus::Params::new(Network::Bitcoin);
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
            real_decode.block_hash_with_scrypt()
        );
        assert_eq!(real_decode.header.difficulty(&params), 455);
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
        // The highest possible target in Dogecoin is defined as 0x1e0ffff0
        let bits = 0x1e0ffff0_u32;
        let want = Target::MAX_ATTAINABLE_MAINNET_DOGE;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want)
    }
}
