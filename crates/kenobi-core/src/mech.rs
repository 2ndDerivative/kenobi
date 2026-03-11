#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    KerberosV5,
    Spnego,
}
