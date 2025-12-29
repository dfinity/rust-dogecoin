<div align="center">
  <h1>Rust Dogecoin</h1>

  <img alt="Rust Dogecoin logo by DFINITY Foundation, see license and source files under /logo" src="https://raw.githubusercontent.com/dfinity/rust-dogecoin/doge-master/logo/rust-btc+doge@4x.png" width="720" />

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Bitcoin and Dogecoin.
  </p>

  <p>
    <a href="https://crates.io/crates/bitcoin-dogecoin"><img alt="Crate Info" src="https://img.shields.io/crates/v/bitcoin-dogecoin.svg"/></a>
    <a href="https://github.com/rust-dogecoin/rust-dogecoin/blob/doge-master/LICENSE"><img alt="Apache License 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/actions?query=workflow%3AContinuous%20integration"><img alt="CI Status" src="https://github.com/dfinity/rust-dogecoin/workflows/Continuous%20integration/badge.svg"></a>
    <a href="https://docs.rs/bitcoin-dogecoin"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs--bitcoin-dogecoin-green"/></a>
    <a href="https://blog.rust-lang.org/2021/11/01/Rust-1.56.1.html"><img alt="Rustc Version 1.56.1+" src="https://img.shields.io/badge/rustc-1.56.1%2B-lightgrey.svg"/></a>
  </p>
</div>

This library is a fork of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin), adapted to support the **Dogecoin** network. For reference, see the original [rust-bitcoin README](https://github.com/dfinity/rust-dogecoin/blob/master/README.md).

The goal of this project is to provide Dogecoin-compatible types, consensus rules, and utilities, following the architecture of rust-bitcoin, in particular:

- **Scrypt PoW**: Scrypt-based proof-of-work validation (instead of SHA-256d used in Bitcoin)
- **AuxPoW/Merged Mining**: AuxPow validation and Dogecoin's merged mining with other chains
- **Difficulty Adjustment**: Dogecoin difficulty adjustment algorithms (pre-Digishield and Digishield)
- **Network Parameters**: Consensus parameters for mainnet, testnet, and regtest
- **Addresses**: Dogecoin-specific base58 addresses (P2PKH and P2SH)
- **Genesis Blocks**: Genesis block definitions for mainnet, testnet, and regtest

## Differences from rust-bitcoin

### 1. Core rust-bitcoin code modifications

The following core files have been modified from the upstream rust-bitcoin library:

- `bitcoin/src/blockdata/block.rs`: Add scrypt-based proof-of-work validation (`block_hash_with_scrypt()` and `validate_pow_with_scrypt()`) to support Dogecoin's scrypt hashing algorithm.

- `bitcoin/src/pow.rs`: Implement Dogecoin's difficulty adjustment algorithms:
  - Pre-Digishield (blocks 0-144,999) with variable transition thresholds based on block height ranges
  - Digishield (blocks 145,000+)
  - Helper methods `min_transition_threshold_dogecoin()` and `max_transition_threshold_dogecoin()` for proper difficulty bounds

- `bitcoin/src/p2p/message.rs`: Generic `RawNetworkMessage` and `NetworkMessage` over `Header` and `Block` types to support both Bitcoin and Dogecoin block and header formats (which can include AuxPoW information).

### 2. Dogecoin-Specific module ([bitcoin/src/dogecoin/](bitcoin/src/dogecoin/))

A Dogecoin module has been added with the following components:

- `mod.rs`: Dogecoin types including:
  - `Header`: Dogecoin block header with optional AuxPoW information
  - `Block`: Dogecoin block structure supporting both legacy and merged-mined blocks
  - `Network`: Dogecoin network enum (mainnet, testnet, regtest)

- `auxpow.rs`: Implementation of Auxiliary Proof-of-Work (merged mining) validation

- `params.rs`: Dogecoin consensus parameters for all networks (mainnet, testnet, regtest), such as Digishield and AuxPoW activation height,
BIP activation heights, target spacing, max attainable targets, etc

- `constants.rs`: Dogecoin-specific constants, such as Genesis block definition, and address prefixes

- `address/`: Dogecoin address handling with support for P2PKH and P2SH address types

**Note**: Advanced Bitcoin features such as Taproot, SegWit v1, and PSBT v2 are not applicable to Dogecoin and are not supported in this fork.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.

To build with the MSRV you will likely need to pin a bunch of dependencies, see `./contrib/test.sh`
for the current list.

## Licensing

This project is a fork of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/tree/master), originally licensed under CC0 v1.0 Universal.

This fork is licensed under the Apache License, Version 2.0, except where otherwise noted.

We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
