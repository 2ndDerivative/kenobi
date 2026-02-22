pub(crate) mod delegation {
    use windows::Win32::Security::Authentication::Identity::{ASC_REQ_DELEGATE, ASC_REQ_FLAGS, ASC_RET_DELEGATE};

    pub trait Sealed {
        const RETURN_FLAGS: u32;
        const REQUEST_FLAGS: ASC_REQ_FLAGS;
    }
    impl Sealed for super::NoDelegation {
        const RETURN_FLAGS: u32 = 0;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_FLAGS(0);
    }
    impl Sealed for super::OfferDelegate {
        const RETURN_FLAGS: u32 = ASC_RET_DELEGATE;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_DELEGATE;
    }
}

pub enum NoDelegation {}
pub enum OfferDelegate {}
pub enum CanDelegate {}
pub trait DelegationPolicy: delegation::Sealed {}
impl<T: delegation::Sealed> DelegationPolicy for T {}

pub(crate) mod sign {
    use windows::Win32::Security::Authentication::Identity::{ASC_REQ_FLAGS, ASC_REQ_INTEGRITY, ASC_RET_INTEGRITY};

    pub trait Sealed {
        const RETURN_FLAGS: u32;
        const REQUEST_FLAGS: ASC_REQ_FLAGS;
    }
    impl Sealed for super::NoSigning {
        const RETURN_FLAGS: u32 = 0;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_FLAGS(0);
    }
    impl Sealed for super::MaybeSign {
        const RETURN_FLAGS: u32 = ASC_RET_INTEGRITY;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_INTEGRITY;
    }
}
pub trait SigningPolicy: sign::Sealed {}
pub enum NoSigning {}
impl SigningPolicy for NoSigning {}
pub enum MaybeSign {}
impl SigningPolicy for MaybeSign {}
pub enum CanSign {}

pub(crate) mod encrypt {
    use windows::Win32::Security::Authentication::Identity::{
        ASC_REQ_CONFIDENTIALITY, ASC_REQ_FLAGS, ASC_RET_CONFIDENTIALITY,
    };

    pub trait Sealed {
        const RETURN_FLAGS: u32;
        const REQUEST_FLAGS: ASC_REQ_FLAGS;
    }
    impl Sealed for super::NoEncryption {
        const RETURN_FLAGS: u32 = 0;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_FLAGS(0);
    }
    impl Sealed for super::MaybeEncrypt {
        const RETURN_FLAGS: u32 = ASC_RET_CONFIDENTIALITY;
        const REQUEST_FLAGS: ASC_REQ_FLAGS = ASC_REQ_CONFIDENTIALITY;
    }
}
pub trait EncryptionPolicy: encrypt::Sealed {}
pub enum NoEncryption {}
impl EncryptionPolicy for NoEncryption {}
pub enum MaybeEncrypt {}
impl EncryptionPolicy for MaybeEncrypt {}
pub enum CanEncrypt {}
