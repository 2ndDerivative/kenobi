use std::marker::PhantomData;

use windows::Win32::Security::Authentication::Identity::{ImpersonateSecurityContext, RevertSecurityContext};

use crate::FinishedServerContext;

pub struct Impersonation<'con> {
    context: &'con mut FinishedServerContext,
    _not_send: PhantomData<*const ()>,
}
impl<'con> Impersonation<'con> {
    pub(crate) fn new(context: &'con mut FinishedServerContext) -> Result<Self, windows::core::Error> {
        unsafe {
            ImpersonateSecurityContext(&context.context_handle)?;
        }
        Ok(Self {
            context,
            _not_send: PhantomData,
        })
    }
    pub fn revert(self) {}
}

impl<'a> Drop for Impersonation<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertSecurityContext(&self.context.context_handle);
        }
    }
}
