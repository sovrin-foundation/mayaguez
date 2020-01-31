/*
 * Copyright 2019 Michael Lodder
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
//! The storage management for aries agents.
//! This layer is composed of the authentication layer
//! the data protection layer, and data persistance layer.
//!
//! Authentication is how a connection to the storage is
//! created and authorized.
//!
//! Data protection handles encrypting/decrypting data
//! depending on how the system is to be architected.
//! This layer could be bundled with authentication and/or
//! the persistance layer. This is decoupled to allow
//! for better flexibility
//!
//! Data persistance is just putting the data where it can
//! be retrieved later. This could be a database, files,
//! cloud storage, or memory.

/// The security module
pub mod security;
