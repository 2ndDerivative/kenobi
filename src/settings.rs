use windows::Win32::Security::Authentication::Identity::{
    ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONFIDENTIALITY, ASC_REQ_CONNECTION, ASC_REQ_DELEGATE, ASC_REQ_INTEGRITY,
    ASC_REQ_REPLAY_DETECT, ASC_REQ_SEQUENCE_DETECT,
};

#[derive(Clone, Copy, Debug)]
pub struct ServerSettings {
    pub datarep: TargetDataRep,
    pub bitflags: u32,
}
impl ServerSettings {
    /// Sets the ``ASC_REQ_DELEGATE`` flag to ask the client
    /// for an unconstrained delegation permission.
    ///
    /// Only works for Kerberos and is not needed for constrained delegation.
    ///
    /// If possible, use constrained delegation to reduce attack surface
    #[must_use]
    pub fn request_unconstrained_delegation(self) -> Self {
        Self {
            datarep: self.datarep,
            bitflags: self.bitflags | ASC_REQ_DELEGATE.0,
        }
    }
    #[must_use]
    /// Does Token buffer allocation on the side of the SSPI package
    pub fn let_sspi_allocate(self) -> Self {
        Self {
            datarep: self.datarep,
            bitflags: self.bitflags | ASC_REQ_ALLOCATE_MEMORY.0,
        }
    }
    #[must_use]
    pub fn lets_sspi_allocate(self) -> bool {
        self.bitflags & ASC_REQ_ALLOCATE_MEMORY.0 != 0
    }
}

impl Default for ServerSettings {
    fn default() -> Self {
        let bitflags = (ASC_REQ_CONNECTION
            | ASC_REQ_CONFIDENTIALITY
            | ASC_REQ_INTEGRITY
            | ASC_REQ_REPLAY_DETECT
            | ASC_REQ_SEQUENCE_DETECT)
            .0;
        Self {
            datarep: TargetDataRep::default(),
            bitflags,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum TargetDataRep {
    Native,
    #[default]
    Network,
}
