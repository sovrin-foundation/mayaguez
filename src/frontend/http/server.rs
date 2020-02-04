//! `AriesWsServer` is an actor that maintains a list of connection client sessions.
//! Peers send messages to this server and receive responses

use actix::prelude::*;
use rand::prelude::*;

pub struct AriesServer {
    rng: ThreadRng
}

impl Default for AriesServer {
    fn default() -> Self {
        Self {
            rng: rand::thread_rng()
        }
    }
}

impl Actor for AriesServer {
    type Context = Context<Self>;
}

