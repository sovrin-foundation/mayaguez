use nom::{
    bytes::complete::{is_a, is_not, tag, take_while},
    character::complete::char,
    combinator::{map, map_res, opt},
    multi::separated_list,
    sequence::preceded,
    IResult
};

#[derive(Debug)]
pub struct SemVer {
    pub major: usize,
    pub minor: usize,
    pub revision: usize
}

#[derive(Debug)]
pub struct MessageTypeUri {
    pub doc_uri: String,
    pub protocol_name: String,
    pub protocol_version: SemVer,
    pub msg_type_name: String
}

