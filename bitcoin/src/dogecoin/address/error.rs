// SPDX-License-Identifier: Apache-2.0

//! Error code for the address module.

use core::fmt;

use internals::write_err;

pub use crate::address::error::{
    FromScriptError, InvalidBase58PayloadLengthError, InvalidLegacyPrefixError,
    LegacyAddressTooLongError, P2shError,
};
use crate::dogecoin::address::{Address, NetworkUnchecked};
use crate::dogecoin::Network;

/// Address parsing error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Base58 error.
    Base58(base58::Error),
    /// Legacy address is too long.
    LegacyAddressTooLong(LegacyAddressTooLongError),
    /// Invalid base58 payload data length for legacy address.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Invalid legacy address prefix in base58 data payload.
    InvalidLegacyPrefix(InvalidLegacyPrefixError),
    /// Address's network differs from required one.
    NetworkValidation(NetworkValidationError),
}

internals::impl_from_infallible!(ParseError);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 error"; e),
            LegacyAddressTooLong(ref e) => write_err!(f, "legacy address base58 string"; e),
            InvalidBase58PayloadLength(ref e) => write_err!(f, "legacy address base58 data"; e),
            InvalidLegacyPrefix(ref e) => write_err!(f, "legacy address base58 prefix"; e),
            NetworkValidation(ref e) => write_err!(f, "validation error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Base58(ref e) => Some(e),
            LegacyAddressTooLong(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            InvalidLegacyPrefix(ref e) => Some(e),
            NetworkValidation(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for ParseError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}

impl From<LegacyAddressTooLongError> for ParseError {
    fn from(e: LegacyAddressTooLongError) -> Self { Self::LegacyAddressTooLong(e) }
}

impl From<InvalidBase58PayloadLengthError> for ParseError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self { Self::InvalidBase58PayloadLength(e) }
}

impl From<InvalidLegacyPrefixError> for ParseError {
    fn from(e: InvalidLegacyPrefixError) -> Self { Self::InvalidLegacyPrefix(e) }
}

impl From<NetworkValidationError> for ParseError {
    fn from(e: NetworkValidationError) -> Self { Self::NetworkValidation(e) }
}

/// Address's network differs from required one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkValidationError {
    /// Network that was required.
    pub(crate) required: Network,
    /// The address itself.
    pub(crate) address: Address<NetworkUnchecked>,
}

impl fmt::Display for NetworkValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "address ")?;
        fmt::Display::fmt(&self.address.0, f)?;
        write!(f, " is not valid on {}", self.required)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetworkValidationError {}
