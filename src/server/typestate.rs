pub(crate) mod delegation {
    use windows::Win32::Security::Authentication::Identity::{ASC_REQ_DELEGATE, ASC_REQ_FLAGS, ASC_RET_DELEGATE};

    use crate::server::typestate::{NoDelegation, OfferDelegate};

    pub trait Sealed {
        const RETURN_FLAGS: u32;
        const REQUEST_FLAGS: ASC_REQ_FLAGS;
    }
    impl Sealed for NoDelegation {
        const RETURN_FLAGS: u32 = 0;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_FLAGS(0);
    }
    impl Sealed for OfferDelegate {
        const RETURN_FLAGS: u32 = ASC_RET_DELEGATE;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_DELEGATE;
    }
}

pub enum NoDelegation {}
pub enum OfferDelegate {}
pub enum CanDelegate {}
pub trait DelegationPolicy: delegation::Sealed {}
impl<T: delegation::Sealed> DelegationPolicy for T {}
