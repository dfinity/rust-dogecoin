// SPDX-License-Identifier: Apache-2.0

//! Dogecoin addresses.
//!
//! Support for ordinary base58 Dogecoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use bitcoin::dogecoin::{Address, Network};
//! use bitcoin::{PublicKey, secp256k1::{rand, Secp256k1}};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Dogecoin);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! bitcoin = { version = "...", features = ["rand-std"] }
//! ```

pub mod error;

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use hashes::Hash;
use secp256k1::XOnlyPublicKey;

use crate::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE;
use crate::blockdata::script::{self, Script, ScriptBuf, ScriptHash};
use crate::crypto::key::{PubkeyHash, PublicKey};
use crate::dogecoin::constants::{
    PUBKEY_ADDRESS_PREFIX_MAINNET, PUBKEY_ADDRESS_PREFIX_REGTEST, PUBKEY_ADDRESS_PREFIX_TESTNET,
    SCRIPT_ADDRESS_PREFIX_MAINNET, SCRIPT_ADDRESS_PREFIX_REGTEST, SCRIPT_ADDRESS_PREFIX_TESTNET,
};
use crate::dogecoin::Network;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    error::{
        FromScriptError, InvalidBase58PayloadLengthError, InvalidLegacyPrefixError, LegacyAddressTooLongError,
        NetworkValidationError, ParseError, P2shError,
    },
};

// Re-export shared types from bitcoin::address.
pub use crate::address::{AddressType, NetworkChecked, NetworkUnchecked, NetworkValidation};

/// The inner representation of an address, without the network validation tag.
///
/// This struct represents the inner representation of an address without the network validation
/// tag, which is used to ensure that addresses are used only on the appropriate network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: PubkeyHash, network: Network },
    P2sh { hash: ScriptHash, network: Network },
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    Network::Dogecoin => PUBKEY_ADDRESS_PREFIX_MAINNET,
                    Network::Testnet => PUBKEY_ADDRESS_PREFIX_TESTNET,
                    Network::Regtest => PUBKEY_ADDRESS_PREFIX_REGTEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    Network::Dogecoin => SCRIPT_ADDRESS_PREFIX_MAINNET,
                    Network::Testnet => SCRIPT_ADDRESS_PREFIX_TESTNET,
                    Network::Regtest => SCRIPT_ADDRESS_PREFIX_REGTEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
        }
    }
}

/// The data encoded by an `Address`.
///
/// This is the data used to encumber an output that pays to this address i.e., it is the address
/// excluding the network information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressData {
    /// Data encoded by a P2PKH address.
    P2pkh {
        /// The pubkey hash used to encumber outputs to this address.
        pubkey_hash: PubkeyHash,
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The script hash used to encumber outputs to this address.
        script_hash: ScriptHash,
    },
}

/// A Dogecoin address.
///
/// ### Parsing addresses
///
/// When parsing string as an address, one has to pay attention to the network, on which the parsed
/// address is supposed to be valid. For the purpose of this validation, `Address` has
/// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
/// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
/// address has been checked. This marker type will prevent from calling certain functions unless the network
/// verification has been successfully completed.
///
/// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
/// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
/// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
/// `Address<NetworkChecked>` is returned.
///
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use bitcoin::dogecoin::{Address, Network};
/// use bitcoin::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Dogecoin).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt").unwrap()
///                .require_network(Network::Dogecoin).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt".parse::<Address<_>>()
///                .unwrap().require_network(Network::Dogecoin).unwrap();
/// ```
///
/// ### Formatting addresses
///
/// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
/// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
///
/// 1. `Display` is implemented only for `Address<NetworkChecked>`:
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::dogecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use bitcoin::dogecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
///    an indicator that its network has not been checked. This is to encourage programmer to properly
///    check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::dogecoin::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::dogecoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe");
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// The `#[repr(transparent)]` attribute is used to guarantee the layout of the `Address` struct. It
// is an implementation detail and users should not rely on it in their code.
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0 .0, fmt)
    }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Dogecoin address");

#[cfg(feature = "serde")]
impl<N: NetworkValidation> serde::Serialize for Address<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }

    /// Marks the network of this address as unchecked.
    pub fn into_unchecked(self) -> Address<NetworkUnchecked> {
        Address(self.0, PhantomData)
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl Into<Network>) -> Address {
        let hash = pk.into();
        Self(AddressInner::P2pkh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: impl Into<Network>) -> Result<Address, P2shError> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(P2shError::ExcessiveScriptSize);
        }
        let hash = script.script_hash();
        Ok(Address::p2sh_from_hash(hash, network))
    }

    /// Creates a pay to script hash P2SH address from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl Into<Network>) -> Address {
        Self(AddressInner::P2sh { hash, network: network.into() }, PhantomData)
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match self.0 {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(&self) -> AddressData {
        use AddressData::*;

        match self.0 {
            AddressInner::P2pkh { hash, network: _ } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, network: _ } => P2sh { script_hash: hash },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match self.0 {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match self.0 {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(
        script: &Script,
        network: impl Into<Network>,
    ) -> Result<Address, FromScriptError> {
        let network = network.into();
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Address::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Address::p2sh_from_hash(hash, network))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } => ScriptBuf::new_p2pkh(hash),
            P2sh { ref hash, network: _ } => ScriptBuf::new_p2sh(hash),
        }
    }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload) || (xonly_pubkey.serialize() == *payload)
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } if script.is_p2pkh() => {
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            P2sh { ref hash, network: _ } if script.is_p2sh() => {
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            P2pkh { .. } | P2sh { .. } => false,
        }
    }

    /// Returns the "payload" for this address.
    ///
    /// The "payload" is the useful stuff excluding serialization prefix, the exact payload is
    /// dependent on the inner address:
    ///
    /// - For p2sh, the payload is the script hash.
    /// - For p2pkh, the payload is the pubkey hash.
    fn payload_as_bytes(&self) -> &[u8] {
        use AddressInner::*;
        match self.0 {
            P2sh { ref hash, network: _ } => hash.as_ref(),
            P2pkh { ref hash, network: _ } => hash.as_ref(),
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    ///
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }

    /// Parsed addresses do not always have *one* network. The problem is that testnet,
    /// regtest p2pkh addresses use different prefixes, but testnet and regtest p2sh
    /// addresses use the same prefix.
    ///
    /// So if one wants to check if an address belongs to a certain network a simple
    /// comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use bitcoin::dogecoin::{Address, Network};
    /// use bitcoin::address::NetworkUnchecked;
    ///
    /// let address: Address<NetworkUnchecked> = "no2dRNaFqxNjWZLeTRu4XyCuzeGdE3VY2S".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert_eq!(address.is_valid_for_network(Network::Regtest), false);
    ///
    /// let address: Address<NetworkUnchecked> = "n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    ///
    /// let address: Address<NetworkUnchecked> = "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Dogecoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    ///
    /// let address: Address<NetworkUnchecked> = "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert_eq!(address.is_valid_for_network(Network::Dogecoin), false);
    /// ```
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { hash: _, ref network } => *network == n,
            P2sh { hash: _, network: Network::Dogecoin } => n == Network::Dogecoin,
            P2sh { hash: _, network: Network::Testnet } => {
                n == Network::Testnet || n == Network::Regtest
            }
            P2sh { hash: _, network: Network::Regtest } => {
                n == Network::Testnet || n == Network::Regtest
            }
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    ///
    /// # Errors
    ///
    /// This function only ever returns the [`ParseError::NetworkValidation`] variant of
    /// `ParseError`. This is not how we normally implement errors in this library but
    /// `require_network` is not a typical function, it is conceptually part of string parsing.
    ///
    ///  # Examples
    ///
    /// ```
    /// use bitcoin::address::{NetworkChecked, NetworkUnchecked};
    /// use bitcoin::dogecoin::{Address, Network, ParseError};
    ///
    /// const ADDR: &str = "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt";
    ///
    /// fn parse_and_validate_address(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()?
    ///                       .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_combinator(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()
    ///                       .and_then(|a| a.require_network(network))?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_show_types(network: Network) -> Result<Address, ParseError> {
    ///     let address: Address<NetworkChecked> = ADDR.parse::<Address<NetworkUnchecked>>()?
    ///                                                .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// let network = Network::Dogecoin;  // Don't hard code network in applications.
    /// let _ = parse_and_validate_address(network).unwrap();
    /// let _ = parse_and_validate_address_combinator(network).unwrap();
    /// let _ = parse_and_validate_address_show_types(network).unwrap();
    /// ```
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkValidationError { required, address: self }.into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address {
        Address(self.0, PhantomData)
    }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self {
        a.script_pubkey()
    }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.0, f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.0, f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Address<NetworkUnchecked>, ParseError> {
        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(InvalidBase58PayloadLengthError { length: s.len() }.into());
        }

        let (prefix, data) = data.split_first().expect("length checked above");
        let data: [u8; 20] = data.try_into().expect("length checked above");

        let inner = match *prefix {
            PUBKEY_ADDRESS_PREFIX_MAINNET => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: Network::Dogecoin }
            }
            PUBKEY_ADDRESS_PREFIX_TESTNET => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: Network::Testnet }
            }
            PUBKEY_ADDRESS_PREFIX_REGTEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: Network::Regtest }
            }
            SCRIPT_ADDRESS_PREFIX_MAINNET => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: Network::Dogecoin }
            }
            SCRIPT_ADDRESS_PREFIX_TESTNET => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: Network::Testnet }
            }
            invalid => return Err(InvalidLegacyPrefixError { invalid }.into()),
        };

        Ok(Address(inner, PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dogecoin::Network::{Dogecoin, Testnet};

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), network)
                .expect("failed to create inner address from script_pubkey"),
            *addr,
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    #[test]
    fn test_p2pkh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, Dogecoin);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "D7ALZLo7BL5vM9Vb4vAqvqwX9fpQ4wKRiy");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Dogecoin);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(key, Dogecoin);
        assert_eq!(&addr.to_string(), "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt");

        let key = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(key, Testnet);
        assert_eq!(&addr.to_string(), "neRuCZsfnZaJN8FmxxVZDSZbcGATnzGByf");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<ScriptHash>().unwrap();
        let addr = Address::p2sh_from_hash(hash, Dogecoin);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap(),
        );
        assert_eq!(&addr.to_string(), "9tTWgUQoVtNuogNtsZWJ3qmE7dkrPTrVAj");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Dogecoin);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, Testnet).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, Testnet), Err(P2shError::ExcessiveScriptSize));
    }

    #[test]
    fn test_address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "n48pquU8ieq7gidgJJ4vWD2jbsErmZvrwe";
        let unchecked = Address::from_str(addr_str).unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked.clone() }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn test_address_type() {
        let addresses = [
            ("DMKhUaRmnxJXfDxyFguMnMjVdgvnNipFzt", Some(AddressType::P2pkh)),
            ("A1yb6viUzAcUWftRHT6GpnCwvhXHg4CV1x", Some(AddressType::P2sh)),
        ];
        for (address, expected_type) in &addresses {
            let addr =
                Address::from_str(address).unwrap().require_network(Dogecoin).expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr =
            Address::from_str("D7ALZLo7BL5vM9Vb4vAqvqwX9fpQ4wKRiy").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("D7ALZLo7BL5vM9Vb4vAqvqwX9fpQ4wKRiy".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );

        let addr =
            Address::from_str("9tTWgUQoVtNuogNtsZWJ3qmE7dkrPTrVAj").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("9tTWgUQoVtNuogNtsZWJ3qmE7dkrPTrVAj".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap()
        );
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let address_string = "neRuCZsfnZaJN8FmxxVZDSZbcGATnzGByf";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Testnet)
            .expect("testnet");

        let pubkey_string = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "DUSamFaUtRQ78DVidoeY3J8keYkQXdinrt";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Dogecoin)
            .expect("mainnet");

        let pubkey_string = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }
}
