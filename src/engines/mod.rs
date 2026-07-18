//! `engines` module
//!
//! This module defines the traits and implementations for the various logical
//! storage engines supported by LuraDB, such as Key-Value, Document, and
//! Relational models.

pub mod json;
pub mod kv;
pub mod lsm;
pub mod rel;

use anyhow::Result;
use std::future::Future;

/// A generic trait for a storage engine.
///
/// This trait defines the basic contract that all logical storage engines
/// (Key-Value, Document, etc.) must adhere to. It provides a simple,
/// asynchronous interface for getting, setting, and deleting data.
///
/// The methods return `impl Future` to allow for `Send` bounds, which is
/// the recommended practice for async functions in public traits.
pub trait StorageEngine: Send + Sync {
    /// Retrieves a value associated with a given key.
    ///
    /// # Arguments
    /// * `key` - The key to look up.
    ///
    /// # Returns
    /// * `Ok(Some(Vec<u8>))` if the key is found.
    /// * `Ok(None)` if the key is not found.
    /// * `Err` if an I/O or other error occurs.
    fn get(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Inserts or updates a key-value pair.
    ///
    /// # Arguments
    /// * `key` - The key to insert or update.
    /// * `value` - The value to associate with the key.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err` if an I/O or other error occurs.
    fn set(&self, key: &[u8], value: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Deletes a key-value pair.
    ///
    /// # Arguments
    /// * `key` - The key to delete.
    ///
    /// # Returns
    /// * `Ok(())` on success, regardless of whether the key existed.
    /// * `Err` if an I/O or other error occurs.
    fn delete(&self, key: &[u8]) -> impl Future<Output = Result<()>> + Send;
}