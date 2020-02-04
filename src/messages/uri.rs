/*
 * Copyright 2020
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
//! Handles Aries URIs both protocol and messages.
//!

use nom::{
    bytes::complete::{is_a, is_not, tag},
    character::complete::char,
    combinator::{map_res, opt},
    IResult,
};

use std::{cmp::Ordering, str::FromStr};

/// Represents a semantic version with an optional tag
///
/// 1
/// 1.0
/// 1.0.0
/// 1.0.0-alpha2
///
/// are all valid
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticVersion {
    /// The major version number
    pub major: usize,
    /// The minor version number, 0 by default
    pub minor: usize,
    /// The revision version number, 0 by default
    pub revision: usize,
    /// The optional tag, "" by default
    pub tag: String,
}

impl Default for SemanticVersion {
    fn default() -> Self {
        Self {
            major: 0,
            minor: 0,
            revision: 0,
            tag: String::new(),
        }
    }
}

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(cmp_semver(self, rhs))
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, rhs: &Self) -> Ordering {
        cmp_semver(self, rhs)
    }
}

impl FromStr for SemanticVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_semver_uri(s.as_bytes()) {
            Ok((_, v)) => Ok(v),
            Err(e) => Err(format!("Invalid semantic version: {:?}", e)),
        }
    }
}

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{}.{}.{}", self.major, self.minor, self.revision);
        if !self.tag.is_empty() {
            s.push_str(self.tag.as_str());
        }
        write!(f, "{}", s)
    }
}

fn cmp_semver(left: &SemanticVersion, right: &SemanticVersion) -> Ordering {
    match left.major.cmp(&right.major) {
        Ordering::Equal => match left.minor.cmp(&right.minor) {
            Ordering::Equal => match left.revision.cmp(&right.revision) {
                Ordering::Equal => left.tag.cmp(&right.tag),
                r => r,
            },
            n => n,
        },
        j => j,
    }
}

fn parse_semver_uri(i: &[u8]) -> IResult<&[u8], SemanticVersion> {
    if i.len() == 0 {
        return Ok((i, SemanticVersion::default()));
    }

    let (i, major) = parse_num(i)?;
    if major.is_none() {
        return Ok((i, SemanticVersion::default()));
    }
    let major = major.unwrap();
    let (i, _) = opt(char('.'))(i)?;
    let (i, minor) = parse_num(i)?;
    let (i, _) = opt(char('.'))(i)?;
    let (i, revision) = parse_num(i)?;
    let (i, tag) = opt(map_res(
        is_a("abcdefghijklmnopqrstuvwxyz0123456789._-"),
        std::str::from_utf8,
    ))(i)?;
    let minor = match minor {
        Some(d) => d,
        None => 0,
    };
    let revision = match revision {
        Some(d) => d,
        None => 0,
    };
    let tag = match tag {
        Some(t) => t.to_string(),
        None => String::new(),
    };
    Ok((
        i,
        SemanticVersion {
            major,
            minor,
            revision,
            tag,
        },
    ))
}

fn parse_num(i: &[u8]) -> IResult<&[u8], Option<usize>> {
    use atoi::FromRadix10Checked;
    match usize::from_radix_10_checked(i) {
        (_, 0) => Ok((i, None)),
        (n, used) => Ok((&i[used..], n)),
    }
}

/// Represents a Message Type Uri
#[derive(Clone, Debug)]
pub struct MessageTypeUri {
    /// The message method
    pub method: String,
    /// The document URI
    pub doc_uri: String,
    /// The protocol name
    pub protocol_name: String,
    /// The protocol version
    pub protocol_version: SemanticVersion,
    /// The message type name
    pub msg_type_name: Option<String>,
}

impl Default for MessageTypeUri {
    fn default() -> Self {
        Self {
            method: String::new(),
            doc_uri: String::new(),
            protocol_name: String::new(),
            protocol_version: SemanticVersion::default(),
            msg_type_name: None,
        }
    }
}

impl FromStr for MessageTypeUri {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 0 {
            return Ok(MessageTypeUri::default());
        }
        let (_, m) = parse_message_type_uri(s.as_bytes()).map_err(|e| format!("{:?}", e))?;
        Ok(m)
    }
}

/// Parse a byte stream into a MessageType
fn parse_message_type_uri(i: &[u8]) -> IResult<&[u8], MessageTypeUri> {
    if i.len() == 0 {
        return Ok((i, MessageTypeUri::default()));
    }

    let (i, _) = tag("did:")(i)?;
    let (i, method) = map_res(
        is_a("abcdefghijklmnopqrstuvwxyz0123456789"),
        std::str::from_utf8,
    )(i)?;
    let (i, _) = char(':')(i)?;
    let (i, doc_uri) = map_res(is_not(";"), std::str::from_utf8)(i)?;
    let (i, _) = tag(";spec/")(i)?;
    let (i, protocol_name) = map_res(is_not("/"), std::str::from_utf8)(i)?;
    let (i, _) = char('/')(i)?;
    let (i, protocol_version) = parse_semver_uri(i)?;
    let (i, _) = opt(tag("/"))(i)?;
    let (i, msg_type_name) = opt(map_res(
        is_a("abccdefghijklmnopqrstuvwxyz0123456789._-"),
        std::str::from_utf8,
    ))(i)?;

    Ok((
        i,
        MessageTypeUri {
            method: method.to_string(),
            doc_uri: doc_uri.to_string(),
            protocol_name: protocol_name.to_string(),
            protocol_version,
            msg_type_name: msg_type_name.map(|s| s.to_string()),
        },
    ))
}

/// All the protocol names supported by Aries
#[derive(Clone, Debug)]
pub enum ProtocolName {
    /// Action menu messages
    ActionMenu,
    /// Basic messages
    BasicMessage,
    /// Connection messages
    Connections,
    /// Credential issuance messages
    CredentialIssuance,
    /// Discover messages
    Discover,
    /// Introduction messages
    Introduction,
    /// Present proof messages
    PresentProof,
    /// Credential presentation messages
    CredentialPresentation,
    /// Notification messages
    Notification,
    /// Routing messages
    Routing,
    /// Trust pring messages
    TrustPing,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_test() {
        for v in vec![
            ("1", 1, 0, 0, String::new()),
            ("0.1", 0, 1, 0, String::new()),
            ("0.1.0", 0, 1, 0, String::new()),
            ("1.0.0-pre3", 1, 0, 0, "-pre3".to_string()),
            ("2.1.111-alpha3", 2, 1, 111, "-alpha3".to_string()),
        ] {
            let res = SemanticVersion::from_str(v.0);
            assert!(res.is_ok());
            let semver = res.unwrap();
            assert_eq!(semver.major, v.1);
            assert_eq!(semver.minor, v.2);
            assert_eq!(semver.revision, v.3);
            assert_eq!(semver.tag, v.4);
        }
    }

    #[test]
    fn message_uri_test() {
        println!(r#"did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/ping"#);
        let res =
            MessageTypeUri::from_str(r#"did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/ping"#);
        println!("{:?}", res);
        assert!(res.is_ok());
        let msg = res.unwrap();
        println!("{:?}", msg);
    }
}
