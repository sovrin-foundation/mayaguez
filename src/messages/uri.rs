use nom::{
    bytes::complete::{is_not, tag, take_until, take_while},
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
    let (i, tag) = opt(map_res(take_while(is_id_char), std::str::from_utf8))(i)?;
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
        (n, used) => Ok((&i[used..], n))
    }
}

/// Represents a Message Type Uri
#[derive(Clone, Debug)]
pub struct MessageTypeUri {
    /// The scheme used by the message type
    pub scheme: String,
    /// The document URI
    pub doc_uri: String,
    /// The protocol name
    pub protocol_name: String,
    /// The protocol version
    pub protocol_version: SemanticVersion,
    /// The message type name
    pub msg_type_name: String,
}

impl Default for MessageTypeUri {
    fn default() -> Self {
        Self {
            scheme: String::new(),
            doc_uri: String::new(),
            protocol_name: String::new(),
            protocol_version: SemanticVersion::default(),
            msg_type_name: String::new()
        }
    }
}

impl FromStr for MessageTypeUri {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_message_type_uri(s.as_bytes()) {
            Ok((_, v)) => Ok(v),
            Err(e) => Err(format!("Invalid message type uri: {:?}", e)),
        }
    }
}

fn parse_message_type_uri(i: &[u8]) -> IResult<&[u8], MessageTypeUri> {
    if i.len() == 0 {
        return Ok((i, MessageTypeUri::default()));
    }

    let (i, scheme) = map_res(take_until("://"), std::str::from_utf8)(i)?;
    let (i, _) = tag("://")(i)?;
    let (i, doc_uri) = map_res(is_not("?/&:;="), std::str::from_utf8)(i)?;
    let (i, protocol_name) = map_res(take_until("/"), std::str::from_utf8)(i)?;
    let (i, _) = tag("/")(i)?;
    let (i, protocol_version) = parse_semver_uri(i)?;
    let (i, _) = tag("/")(i)?;
    let (i, msg_type_name) = map_res(take_while(is_id_char), std::str::from_utf8)(i)?;

    Ok((
        i,
        MessageTypeUri {
            scheme: scheme.to_string(),
            doc_uri: doc_uri.to_string(),
            protocol_name: protocol_name.to_string(),
            protocol_version,
            msg_type_name: msg_type_name.to_string(),
        },
    ))
}

fn is_id_char(c: u8) -> bool {
    let c = c as char;
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_test() {
        let res = SemanticVersion::from_str("1.0");
        assert!(res.is_ok());
        let semver = res.unwrap();
        assert_eq!(semver.major, 1);
        assert_eq!(semver.minor, 0);
        assert_eq!(semver.revision, 0);
        assert_eq!(semver.tag, String::new());
    }
}
