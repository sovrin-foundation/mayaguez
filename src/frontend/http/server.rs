//! `AriesWsServer` is an actor that maintains a list of connection client sessions.
//! Peers send messages to this server and receive responses

use actix::prelude::*;
use rand::prelude::*;
use std::collections::BTreeMap;
use std::sync::mpsc::{Sender, Receiver};

pub struct AriesWsServer {
    channels: BTreeMap<usize, (Sender, Receiver)>;
    rng: ThreadRng
}

impl Default for AriesWsServer {
    fn default() -> Self {
        Self {
            channels: BTreeMap::new()
            rng: rand::thread_rng()
        }
    }
}

impl Actor for AriesWsServer {
    type Context = Context<Self>;
}

