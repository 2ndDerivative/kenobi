use kenobi_core::{channel_bindings::Channel, cred::usage::InboundUsable};

use crate::{cred::Credentials, server::StepOut};

#[derive(Debug)]
pub struct ServerBuilder<Usage> {
    #[cfg(windows)]
    inner: kenobi_windows::server::ServerBuilder<Usage>,
}
impl<Usage> ServerBuilder<Usage> {
    pub fn bind_to_channel<C: Channel>(self, channel: &C) -> Result<Self, C::Error> {
        let inner = self.inner.bind_to_channel(channel)?;
        Ok(Self { inner })
    }
}

#[cfg(windows)]
impl<Usage: InboundUsable> ServerBuilder<Usage> {
    #[must_use]
    pub fn new_from_credentials(cred: Credentials<Usage>) -> Self {
        let inner = kenobi_windows::server::ServerBuilder::new_from_credentials(cred.inner);
        ServerBuilder { inner }
    }
}

#[cfg(windows)]
impl<Usage: InboundUsable> ServerBuilder<Usage> {
    #[must_use]
    pub fn initialize(self, token: &[u8]) -> StepOut<Usage> {
        StepOut::from_windows(self.inner.initialize(token).unwrap())
    }
}
