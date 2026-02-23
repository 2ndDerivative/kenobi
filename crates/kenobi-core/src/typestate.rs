pub trait PreAuthState {}

pub enum NoSigning {}
pub enum MaybeSigning {}
pub enum Signing {}

pub enum NoEncryption {}
pub enum MaybeEncryption {}
pub enum Encryption {}
