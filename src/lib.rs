//! signoff — is the service really done?
//!
//! Every measurement goes through [`runner::Runner`], so the verdict logic
//! is testable against recorded answers without a host.
pub mod app;
pub mod checks;
pub mod cli;
pub mod config;
pub mod curlrc;
pub mod guest;
pub mod runner;
pub mod time;
pub mod verdict;
