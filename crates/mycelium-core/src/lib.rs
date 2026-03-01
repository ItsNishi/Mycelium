/// Mycelium core -- types, traits, errors, and policy engine.
///
/// This crate has zero required dependencies. The optional `serde` feature
/// adds Serialize/Deserialize derives to all public types.

pub mod audit;
pub mod error;
pub mod platform;
pub mod policy;
pub mod types;

pub use error::{MyceliumError, Result};
