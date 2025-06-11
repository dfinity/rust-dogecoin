// SPDX-License-Identifier: Apache-2.0

//! Dogecoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Dogecoin
//! chains (such as mainnet, testnet, regtest).
//!

use crate::dogecoin::Network;
use crate::network::Network as BitcoinNetwork;
use crate::params::Params as BitcoinParams;
use crate::Target;

/// Parameters that influence chain consensus.
#[derive(Debug, Clone)]
pub struct Params {
    /// Parameters inherited from Bitcoin, reused for Dogecoin consensus.
    pub bitcoin_params: BitcoinParams,
    /// Parameters that are not inherited from Bitcoin.
    pub dogecoin_params: DogecoinParams,
}

/// Dogecoin-specific consensus parameters.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DogecoinParams {
    /// Network for which parameters are valid.
    pub network: Network,
}

/// The mainnet parameters.
///
/// Use this for a static reference e.g., `&params::MAINNET`.
///
/// For more on static vs const see The Rust Reference [using-statics-or-consts] section.
///
/// [using-statics-or-consts]: <https://doc.rust-lang.org/reference/items/static-items.html#using-statics-or-consts>
pub static MAINNET: Params = Params::MAINNET;
/// The dogecoin testnet parameters.
pub static TESTNET: Params = Params::TESTNET;
/// The dogecoin regtest parameters.
pub static REGTEST: Params = Params::REGTEST;

impl Params {
    /// The mainnet parameters (alias for `Params::MAINNET`).
    pub const DOGECOIN: Params = Params::MAINNET;

    /// The mainnet parameters.
    pub const MAINNET: Params = Params {
        bitcoin_params: BitcoinParams {
            network: BitcoinNetwork::Bitcoin,
            bip16_time: 1333238400,                 // Apr 1 2012
            bip34_height: 1034383, // 80d1364201e5df97e696c03bdd24dc885e8617b9de51e453c10a4f629b1e797a
            bip65_height: 3464751, // 34cd2cbba4ba366f47e5aa0db5f02c19eba2adf679ceb6653ac003bdc9a0ef1f
            bip66_height: 1034383, // 80d1364201e5df97e696c03bdd24dc885e8617b9de51e453c10a4f629b1e797a
            rule_change_activation_threshold: 9576, // 95% of 10,080
            miner_confirmation_window: 10080, // 60 * 24 * 7 = 10,080 blocks, or one week
            pow_limit: Target::MAX_ATTAINABLE_MAINNET_DOGE,
            max_attainable_target: Target::MAX_ATTAINABLE_MAINNET_DOGE,
            pow_target_spacing: 60,           // 1 minute
            pow_target_timespan: 4 * 60 * 60, // pre-digishield: 4 hours
            allow_min_difficulty_blocks: false,
            no_pow_retargeting: false,
        },
        dogecoin_params: DogecoinParams { network: Network::Dogecoin },
    };

    /// The Dogecoin testnet parameters.
    pub const TESTNET: Params = Params {
        bitcoin_params: BitcoinParams {
            network: BitcoinNetwork::Testnet,
            bip16_time: 1333238400,                 // Apr 1 2012
            bip34_height: 708658, // 21b8b97dcdb94caa67c7f8f6dbf22e61e0cfe0e46e1fff3528b22864659e9b38
            bip65_height: 1854705, // 955bd496d23790aba1ecfacb722b089a6ae7ddabaedf7d8fb0878f48308a71f9
            bip66_height: 708658, // 21b8b97dcdb94caa67c7f8f6dbf22e61e0cfe0e46e1fff3528b22864659e9b38
            rule_change_activation_threshold: 2880, // 2 days (note this is significantly lower than Bitcoin standard)
            miner_confirmation_window: 10080,       // 60 * 24 * 7 = 10,080 blocks, or one week
            pow_limit: Target::MAX_ATTAINABLE_TESTNET_DOGE,
            max_attainable_target: Target::MAX_ATTAINABLE_TESTNET_DOGE,
            pow_target_spacing: 60,           // 1 minute
            pow_target_timespan: 4 * 60 * 60, // pre-digishield: 4 hours
            allow_min_difficulty_blocks: true,
            no_pow_retargeting: false,
        },
        dogecoin_params: DogecoinParams { network: Network::Testnet },
    };

    /// The Dogecoin regtest parameters.
    pub const REGTEST: Params = Params {
        bitcoin_params: BitcoinParams {
            network: BitcoinNetwork::Regtest,
            bip16_time: 1333238400,  // Apr 1 2012
            bip34_height: 100000000, // not activated on regtest
            bip65_height: 1351,
            bip66_height: 1251,                    // used only in rpc tests
            rule_change_activation_threshold: 540, // 75%
            miner_confirmation_window: 720,
            pow_limit: Target::MAX_ATTAINABLE_REGTEST_DOGE,
            max_attainable_target: Target::MAX_ATTAINABLE_REGTEST_DOGE,
            pow_target_spacing: 1,            // regtest: 1 second blocks
            pow_target_timespan: 4 * 60 * 60, // pre-digishield: 4 hours
            allow_min_difficulty_blocks: true,
            no_pow_retargeting: true,
        },
        dogecoin_params: DogecoinParams { network: Network::Regtest },
    };

    /// Creates parameters set for the given network.
    pub const fn new(network: Network) -> Self {
        match network {
            Network::Dogecoin => Params::MAINNET,
            Network::Testnet => Params::TESTNET,
            Network::Regtest => Params::REGTEST,
        }
    }
}

impl AsRef<BitcoinParams> for Params {
    fn as_ref(&self) -> &BitcoinParams { &self.bitcoin_params }
}

impl AsRef<Params> for Params {
    fn as_ref(&self) -> &Params { self }
}
