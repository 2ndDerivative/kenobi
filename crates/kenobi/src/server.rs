pub use builder::ServerBuilder;
use kenobi_core::{
    cred::usage::InboundUsable,
    typestate::{MaybeDelegation, MaybeEncryption, MaybeSigning},
};
#[cfg(unix)]
use kenobi_unix::server::{
    PendingServerContext as UnixPendingContext, ServerContext as UnixContext, StepOut as UnixStepOut,
};

#[cfg(windows)]
use kenobi_windows::server::{
    PendingServerContext as WinPendingContext, ServerContext as WinContext, StepOut as WinStepOut,
};

mod builder;

pub struct ServerContext<Usage> {
    #[cfg(windows)]
    inner: WinContext<Usage, MaybeSigning, MaybeEncryption, MaybeDelegation>,
    #[cfg(unix)]
    inner: UnixContext<Usage, MaybeSigning, MaybeEncryption, MaybeDelegation>,
}

impl<Usage> ServerContext<Usage> {
    #[must_use]
    pub fn last_token(&self) -> Option<&[u8]> {
        self.inner.last_token()
    }
    pub fn client_name(&mut self) -> impl std::fmt::Display + Send + Sync {
        self.inner.client_name().unwrap()
    }
}

pub struct PendingServerContext<Usage> {
    #[cfg(windows)]
    inner: WinPendingContext<Usage>,
    #[cfg(unix)]
    inner: UnixPendingContext<Usage>,
}

impl<Usage> PendingServerContext<Usage> {
    #[must_use]
    pub fn next_token(&self) -> &[u8] {
        self.inner.next_token()
    }
}

#[cfg(windows)]
impl<Usage: InboundUsable> PendingServerContext<Usage> {
    pub fn step(self, token: &[u8]) -> StepOut<Usage> {
        match self.inner.step(token).unwrap() {
            WinStepOut::Pending(inner) => StepOut::Pending(PendingServerContext { inner }),
            WinStepOut::Completed(inner) => StepOut::Finished(ServerContext { inner }),
        }
    }
}
#[cfg(unix)]
impl<Usage: InboundUsable> PendingServerContext<Usage> {
    pub fn step(self, token: &[u8]) -> StepOut<Usage> {
        match self.inner.step(token) {
            UnixStepOut::Pending(inner) => StepOut::Pending(PendingServerContext { inner }),
            UnixStepOut::Finished(inner) => StepOut::Finished(ServerContext { inner }),
        }
    }
}

pub enum StepOut<Usage> {
    Pending(PendingServerContext<Usage>),
    Finished(ServerContext<Usage>),
}
impl<Usage> StepOut<Usage> {
    #[cfg(windows)]
    fn from_windows(win: WinStepOut<Usage>) -> StepOut<Usage> {
        match win {
            WinStepOut::Completed(inner) => Self::Finished(ServerContext { inner }),
            WinStepOut::Pending(inner) => Self::Pending(PendingServerContext { inner }),
        }
    }
    #[cfg(unix)]
    fn from_unix(unix: UnixStepOut<Usage>) -> StepOut<Usage> {
        match unix {
            UnixStepOut::Pending(inner) => Self::Pending(PendingServerContext { inner }),
            UnixStepOut::Finished(inner) => Self::Finished(ServerContext { inner }),
        }
    }
}
