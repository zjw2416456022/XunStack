#![forbid(unsafe_code)]
//! Framework-independent contracts and pure, bounded detection logic.
pub mod model;
pub mod baseline;
pub mod rules;
pub mod vulnerability;
pub mod policy;
pub use model::*;
pub const RULE_VERSION: &str = "native-2026.09.15-alpha.1";
