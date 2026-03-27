use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable};

#[cfg(unix)]
use crate::server::AcceptError;
use crate::{cred::Credentials, server::StepOut};

#[derive(Debug)]
pub struct ServerBuilder<Usage> {
    #[cfg(windows)]
    inner: kenobi_windows::server::ServerBuilder<Usage>,
    #[cfg(unix)]
    inner: kenobi_unix::server::ServerBuilder<Usage>,
}
impl<Usage> ServerBuilder<Usage> {
    pub fn bind_to_channel(self, channel: &impl Channel) -> Result<Self, impl std::error::Error> {
        match self.inner.bind_to_channel(channel) {
            Ok(inner) => Ok(Self { inner }),
            Err(e) => Err(e),
        }
    }
}
#[cfg(windows)]
impl<Usage> ServerBuilder<Usage> {
    pub fn with_mutual_auth(self) -> Self {
        let inner = self.inner.offer_mutual_auth();
        Self { inner }
    }
}
#[cfg(unix)]
impl<Usage> ServerBuilder<Usage> {
    pub fn with_mutual_auth(self) -> Self {
        self
    }
}

#[cfg(windows)]
impl<Usage: InboundUsable> ServerBuilder<Usage> {
    #[must_use]
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        let inner = kenobi_windows::server::ServerBuilder::new_from_credentials(cred.inner);
        ServerBuilder { inner }
    }
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage>, AcceptError> {
        Ok(StepOut::from_windows(self.inner.initialize(token).unwrap()))
    }
}
#[cfg(unix)]
impl<Usage: InboundUsable> ServerBuilder<Usage> {
    #[must_use]
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        let inner = kenobi_unix::server::ServerBuilder::new(cred.inner);
        ServerBuilder { inner }
    }
    pub fn initialize(self, token: &[u8]) -> Result<StepOut<Usage>, AcceptError> {
        self.inner
            .initialize(token)
            .map_err(AcceptError::from)
            .map(StepOut::from_unix)
    }
}
