// SPDX-License-Identifier: Apache-2.0

//! Dogecoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Dogecoin
//! chains (such as mainnet, testnet, regtest).
//!

use crate::dogecoin::Network;
use crate::{CompactTarget, Target};

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP16 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP34 becomes active.
    pub bip34_height: u32,
    /// Block height at which BIP65 becomes active.
    pub bip65_height: u32,
    /// Block height at which BIP66 becomes active.
    pub bip66_height: u32,
    /// Minimum blocks including miner confirmation.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// Proof of work limit value. It contains the lowest possible difficulty.
    #[deprecated(since = "0.32.0", note = "field renamed to max_attainable_target")]
    pub pow_limit: Target,
    /// The maximum **attainable** target value for these params.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    ///
    /// Note that this value differs from Dogecoin Core's powLimit field in that this value is
    /// attainable, but Dogecoin Core's is not. Specifically, because targets in Bitcoin are always
    /// rounded to the nearest float expressible in "compact form", not all targets are attainable.
    /// Still, this should not affect consensus as the only place where the non-compact form of
    /// this is used in Dogecoin Core's consensus algorithm is in comparison and there are no
    /// compact-expressible values between Dogecoin Core's and the limit expressed here.
    pub max_attainable_target: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
    /// Determines whether Digishield is used for difficulty adjustment.
    pub digishield_activation_height: u32,
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
            network: Network::Dogecoin,
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
            digishield_activation_height: 145000,
    };

    /// The Dogecoin testnet parameters.
    pub const TESTNET: Params = Params {
            network: Network::Testnet,
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
            digishield_activation_height: 145000,
    };

    /// The Dogecoin regtest parameters.
    pub const REGTEST: Params = Params {
            network: Network::Regtest,
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
            digishield_activation_height: 10,
    };

    /// Creates parameters set for the given network.
    pub const fn new(network: Network) -> Self {
        match network {
            Network::Dogecoin => Params::MAINNET,
            Network::Testnet => Params::TESTNET,
            Network::Regtest => Params::REGTEST,
        }
    }

    /// Checks if Digishield difficulty adjustment is activated at the given block height.
    pub const fn digishield_activated(&self, height: u32) -> bool {
         height >= self.digishield_activation_height
    }

}

impl AsRef<Params> for Params {
    fn as_ref(&self) -> &Params { self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digishield_activation() {
        let pre_digishield_heights = vec![5_000, 10_000, 144_999];
        let digishield_heights = vec![145_000, 145_001, 1_000_000];
        let params = vec![Params::MAINNET, Params::TESTNET];
        for param in params {
            for &height in pre_digishield_heights.iter() {
                assert!(!param.digishield_activated(height));
            }
            for &height in digishield_heights.iter() {
                assert!(param.digishield_activated(height));
            }
        }
    }
}
