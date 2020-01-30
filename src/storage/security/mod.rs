/*
 * Copyright 2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */
//! Security can be managed by two parts: hardware enclaves or software enclaves.
//! 
//! Enclaves are assumed to be specialized crypto modules, usually in hardware,
//! that have been audited for compliance and security. These should be used
//! for key storage and crypto operations to better protect against side channel
//! attacks and key extraction methods. The downside to hardware enclaves is portability.
//! Private keys usually cannot be removed from the enclave and thus presents a 
//! problem for backup and recovery. Keys that need to backup and recovery
//! should not be stored solely in hardware enclaves. Instead, use the hardware to 
//! wrap/unwrap those keys.
//! 
//! Software enclaves usually do not provide the same guarantees as hardware but
//! have the flexibility of portability and deployment. The best approach is use
//! a combination of these two to create an optimal solution. 
//! 
//! For example, use the software enclave provided by the operating system to
//! store credentials to the hardware or external enclave. Once the credentials
//! are retrieved from the OS enclave, they can be used to connect to the 
//! hardware or external enclave.

use failure::{Backtrace, Context, Fail};
use std::{fmt, path::Path};
use zeroize::Zeroize;

/// Typical result from performing and enclave operation or sending an enclave message
pub type EnclaveResult<T> = Result<T, EnclaveError>;

/// Enclave Errors from failures
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum EnclaveErrorKind {
    /// Occurs when a connection cannot be made to the enclave
    #[fail(display = "An error occurred while connecting to the enclave: {}", msg)]
    ConnectionFailure {
        /// Description of what failed during the connection
        msg: String
    },
    /// Occurs when the incorrect credentials are supplied to the enclave
    #[fail(display = "Access was denied to the enclave: {}", msg)]
    AccessDenied {
        /// Description of how access was denied
        msg: String
    },
    /// When a item in the enclave is does not exist
    #[fail(display = "The specified item is not found in the keyring")]
    ItemNotFound,
    /// Catch all if currently not handled or doesn't meet another error category like a general message
    #[fail(display = "{}", msg)]
    GeneralError { 
        /// Generic message
        msg: String 
    }
}

/// Wrapper class for `EnclaveErrorKind`, `Backtrace`, and `Context`
#[derive(Debug)]
pub struct EnclaveError {
    /// The error kind that occurred
    inner: Context<EnclaveErrorKind>
}

impl EnclaveError {
    /// Create from a message and kind
    pub fn from_msg<D: fmt::Display + fmt::Debug + Send + Sync + 'static>(kind: EnclaveErrorKind, msg: D) -> Self {
        Self {
            inner: Context::new(msg).context(kind)
        }
    }

    /// Extract the internal error kind
    pub fn kind(&self) -> EnclaveErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<EnclaveErrorKind> for EnclaveError {
    fn from(e: EnclaveErrorKind) -> Self {
        Self {
            inner: Context::new("").context(e)
        }
    }
}

impl Fail for EnclaveError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for cause in Fail::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl From<security_framework::base::Error> for EnclaveError {
    fn from(e: security_framework::base::Error) -> Self {
        match e.code() {
            -128 => EnclaveErrorKind::AccessDenied { msg: format!("{:?}", e.to_string()) }.into(),
            -25300 => EnclaveErrorKind::ItemNotFound.into(),
            _ => EnclaveErrorKind::GeneralError { msg: "Unknown error".to_string() }.into()
        }
    }
}

/// Configuration options for connecting to Secure Enclaves
/// 
/// Each enclave has its own unique configuration requirements
/// but are wrapped by this config to enable generic interfaces
/// 
/// Enclaves are meant for secure handling of keys. Some enclaves
/// support more crypto primitives like encryption and signatures.
/// For now, we do not support attestations as these are often
/// broken anyway and complex.
#[derive(Debug)]
pub enum EnclaveConfig<A, B> where A: AsRef<Path>, B: Into<String> {
    /// Connect to an instance of an OsKeyRing
    OsKeyRing(OsKeyRingConfig<A, B>),
    /// Connect to a Yubihsm
    YubiHsm
}

impl<A, B> fmt::Display for EnclaveConfig<A, B> where A: AsRef<Path>, B: Into<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnclaveConfig ({})", self)
    }
}

/// Configuration options for connecting to the OS Keying which
/// may be backed by a hardware enclave
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct OsKeyRingConfig<A: AsRef<Path>, B: Into<String>> {
    /// Path to the keyring. If `None`, it will use the default OS keyring
    path: Option<A>,
    /// The username to use for logging in. If `None`, the user will be prompted
    username: Option<B>,
    /// The password to use for logging in. If `None`, the user will be prompted
    password: Option<B>
}

impl<A, B> fmt::Display for OsKeyRingConfig<A, B> where A: AsRef<Path>, B: Into<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OsKeyRingConfig (path: {:?}, username: {:?}, password: {:?})",
                  self.path.as_ref().map(|p| p.as_ref().as_os_str()),
                  self.username.as_ref().map(|_| "*********"),
                  self.password.as_ref().map(|_| "*********"))
    }
}

/// All enclaves structs should use this trait so the callers
/// can simply use them without diving into the details
/// for each unique configuration. This trait is meant
/// to be used by the non-security minded and should be hard
/// to mess up––misuse resistant.
pub trait EnclaveLike: Sized {
    /// Establish a connection to the enclave
    fn connect<A: AsRef<Path>, B: Into<String>>(config: EnclaveConfig<A, B>) -> EnclaveResult<Self>;
    /// Close the connection to the enclave
    fn close(self);
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;