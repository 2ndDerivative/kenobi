use windows::Win32::Security::Authentication::Identity::{
    ISC_REQ_CONFIDENTIALITY, ISC_REQ_FLAGS, ISC_REQ_INTEGRITY, ISC_RET_CONFIDENTIALITY, ISC_RET_INTEGRITY,
};

macro_rules! sealed_policy_trait {
    ($trayt:ident, $module:ident, $not_enforced:ident, $mandatory:ident, $optional:ident, $flag:expr, $return_flag:expr) => {
        pub(crate) mod $module {
            use windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS;

            pub trait Sealed: Sized {
                const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0);
                fn requirements_met_initialization(_attr: u32) -> bool;
                fn requirements_met_manual(_attr: u32) -> bool;
            }
        }
        pub enum $not_enforced {}
        pub enum $mandatory {}
        pub enum $optional {}

        impl<T: $module::Sealed> $trayt for T {}
        pub trait $trayt: $module::Sealed {}
        impl $module::Sealed for $not_enforced {
            fn requirements_met_initialization(_attr: u32) -> bool {
                true
            }
            fn requirements_met_manual(_attr: u32) -> bool {
                unreachable!()
            }
        }
        impl $module::Sealed for $mandatory {
            const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = $flag;
            fn requirements_met_initialization(attr: u32) -> bool {
                attr & $return_flag == $return_flag
            }
            fn requirements_met_manual(_attr: u32) -> bool {
                unreachable!()
            }
        }
        impl $module::Sealed for $optional {
            const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = $flag;
            fn requirements_met_initialization(_attr: u32) -> bool {
                true
            }
            fn requirements_met_manual(attr: u32) -> bool {
                attr & $return_flag == $return_flag
            }
        }
    };
}
sealed_policy_trait!(
    EncryptionPolicy,
    encryption,
    CannotEncrypt,
    CanEncrypt,
    MaybeEncrypt,
    ISC_REQ_FLAGS(ISC_REQ_CONFIDENTIALITY.0 | ISC_REQ_INTEGRITY.0),
    ISC_RET_CONFIDENTIALITY
);
sealed_policy_trait!(
    SigningPolicy,
    signing,
    CannotSign,
    CanSign,
    MaybeSign,
    ISC_REQ_INTEGRITY,
    ISC_RET_INTEGRITY
);

pub(crate) mod delegate {
    use windows::Win32::Security::Authentication::Identity::{ISC_REQ_DELEGATE, ISC_REQ_FLAGS};

    use super::{Delegatable, NoDelegation};

    pub trait Sealed {
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0);
        const RETURN_FLAGS: u32 = 0;
    }
    impl Sealed for NoDelegation {}
    impl Sealed for Delegatable {
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_DELEGATE;
    }
}

pub trait DelegationPolicy: delegate::Sealed {}
pub enum NoDelegation {}
pub enum Delegatable {}
impl<T: delegate::Sealed> DelegationPolicy for T {}
