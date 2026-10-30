//! Pure tunnelgate logic, without I/O: what the operator should send to Cloudflare given the
//! desired and current state. Controllers call into this; most behavior is tested here.

pub mod access;
pub mod dns;
pub mod duration;
pub mod gateway;
pub mod ingress;
pub mod marker;
pub mod sweep;
