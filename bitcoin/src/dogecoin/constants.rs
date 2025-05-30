use hashes::{sha256d, Hash};
use units::Amount;

use crate::dogecoin::params::Params;
use crate::dogecoin::{Block, Network};
use crate::opcodes::all::OP_CHECKSIG;
use crate::{
    absolute, block, script, transaction, CompactTarget, OutPoint, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};

// This is the 65 byte (uncompressed) pubkey used as the one-and-only output of the genesis transaction.
//
// ref: https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L55
// Note output script includes a leading 0x41 and trailing 0xac (added below using the `script::Builder`).
#[rustfmt::skip]
const GENESIS_OUTPUT_PK: [u8; 65] = [
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

/// Constructs and returns the coinbase (and only) transaction of the Dogecoin genesis block.
pub fn dogecoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let (in_script, out_script) = (
        script::Builder::new()
            .push_int(486604799)
            .push_int_non_minimal(4)
            .push_slice(b"Nintondo")
            .into_script(),
        script::Builder::new().push_slice(GENESIS_OUTPUT_PK).push_opcode(OP_CHECKSIG).into_script(),
    );

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
#[allow(dead_code)]
pub fn genesis_block(params: impl AsRef<Params>) -> Block {
    let params = params.as_ref();
    let txdata = vec![dogecoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].compute_txid().into();
    let merkle_root: TxMerkleNode = hash.into();

    match params.dogecoin_params.network {
        Network::Dogecoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1386325540,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 99943,
            },
            auxpow: None,
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1391503289,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 997879,
            },
            auxpow: None,
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
            },
            auxpow: None,
            txdata,
        },
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::encode::serialize;

    #[test]
    fn genesis_first_transaction() {
        let gen = dogecoin_genesis_tx();

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig), hex!("1004ffff001d0104084e696e746f6e646f"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("4341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac"));
        assert_eq!(gen.output[0].value, Amount::from_str("88 BTC").unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.compute_wtxid().to_string(),
            "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"
        );
    }

    #[test]
    fn genesis_full_block() {
        let gen = genesis_block(&Params::DOGECOIN);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"
        );

        assert_eq!(gen.header.time, 1386325540);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 99943);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(&Params::TESTNET);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"
        );
        assert_eq!(gen.header.time, 1391503289);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 997879);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e"
        );
    }

    #[test]
    fn regtest_genesis_full_block() {
        let gen = genesis_block(&Params::REGTEST);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x207fffff));
        assert_eq!(gen.header.nonce, 2);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"
        );
    }
}
