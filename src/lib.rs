use std::{ffi::OsStr, mem::MaybeUninit};

use windows::Win32::{
    Foundation::{
        SEC_E_INSUFFICIENT_MEMORY, SEC_E_INVALID_PARAMETER, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_OK,
    },
    Security::{
        Authentication::Identity::{
            AcceptSecurityContext, SecBufferDesc, ASC_REQ_FLAGS, SECBUFFER_VERSION, SECURITY_NATIVE_DREP,
            SECURITY_NETWORK_DREP,
        },
        Credentials::SecHandle,
    },
};

pub use settings::{ServerSettings, TargetDataRep};

use crate::{
    buffer::{MaybeAllocatedBuffer, ReadOnlySecBuffer},
    credentials::CredentialsHandle,
    impersonate::Impersonation,
};

mod buffer;
mod credentials;
mod impersonate;
mod settings;

pub fn new_server_context(spn: &OsStr, settings: ServerSettings, token: &[u8]) -> Result<StepOk, StartContextError> {
    let cred_handle = CredentialsHandle::acquire(spn).map_err(StartContextError::AcquireCredentials)?;
    let mut input_buffer =
        [ReadOnlySecBuffer::from_slice(token).map_err(|_| StartContextError::Step(StepError::TokenTooLong))?];
    let single_buffer_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: input_buffer[0].buffer_mut(),
    };
    step(cred_handle, settings, None, single_buffer_desc).map_err(StartContextError::Step)
}

pub struct FinishedServerContext {
    credentials_handle: CredentialsHandle,
    buffer_and_settings: MaybeAllocatedBuffer,
    context_handle: SecHandle,
    expiry: i64,
    negotiated_flags: u32,
}
impl FinishedServerContext {
    pub fn impersonate_client(&mut self) -> Result<Impersonation<'_>, windows::core::Error> {
        Impersonation::new(self)
    }
}

pub struct PendingServerContext {
    credentials_handle: CredentialsHandle,
    buffer_and_settings: MaybeAllocatedBuffer,
    context_handle: SecHandle,
}

impl PendingServerContext {
    pub fn step(self, token: &[u8]) -> Result<StepOk, StepError> {
        let Self {
            credentials_handle,
            buffer_and_settings,
            context_handle,
            ..
        } = self;
        let mut buf = [buffer::ReadOnlySecBuffer::from_slice(token).map_err(|_| StepError::TokenTooLong)?];
        let single_buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: buf[0].buffer_mut(),
        };
        step(
            credentials_handle,
            buffer_and_settings.server_settings(),
            Some(context_handle),
            single_buffer_desc,
        )
    }
}

fn step(
    credentials_handle: CredentialsHandle,
    settings: ServerSettings,
    ctx_handle: Option<SecHandle>,
    input_sec_buffer_desc: SecBufferDesc,
) -> Result<StepOk, StepError> {
    // Context handle management
    let is_first = ctx_handle.is_none();
    let mut ctx_handle = ctx_handle.map_or(MaybeUninit::uninit(), MaybeUninit::new);
    let in_ctx_pointer = (!is_first).then_some(ctx_handle.as_ptr());

    // Buffers
    let mut buffer_and_settings =
        MaybeAllocatedBuffer::new(settings).expect("OS returned invalid maximum package size");
    let mut desc = buffer_and_settings.as_desc();

    // Misc outputs
    let mut negotiated_context_flags = MaybeUninit::uninit();
    let mut expiry = MaybeUninit::uninit();
    let asc_result = unsafe {
        AcceptSecurityContext(
            Some(&credentials_handle.sec_handle()),
            in_ctx_pointer,
            Some(&input_sec_buffer_desc),
            ASC_REQ_FLAGS(settings.bitflags),
            match settings.datarep {
                TargetDataRep::Native => SECURITY_NATIVE_DREP,
                TargetDataRep::Network => SECURITY_NETWORK_DREP,
            },
            Some(ctx_handle.as_mut_ptr()),
            Some(&raw mut desc),
            negotiated_context_flags.as_mut_ptr(),
            Some(expiry.as_mut_ptr()),
        )
    };
    match asc_result {
        SEC_E_OK => {
            // These are all set after successful operation
            let context_handle = unsafe { ctx_handle.assume_init() };
            let expiry = unsafe { expiry.assume_init() };
            let negotiated_flags = unsafe { negotiated_context_flags.assume_init() };
            Ok(StepOk::Finished(FinishedServerContext {
                credentials_handle,
                buffer_and_settings,
                context_handle,
                expiry,
                negotiated_flags,
            }))
        }
        SEC_E_INVALID_TOKEN => Err(StepError::InvalidToken),
        SEC_E_INVALID_PARAMETER => Err(StepError::InvalidHandle),
        SEC_E_INSUFFICIENT_MEMORY => Err(StepError::InsufficientMemory),
        SEC_E_LOGON_DENIED => Err(StepError::LogonFailed),
        e => todo!("Error {e} unhandled yet"),
    }
}

pub enum StepOk {
    Continue(PendingServerContext),
    Finished(FinishedServerContext),
}

#[derive(Debug)]
pub enum StartContextError {
    AcquireCredentials(windows_result::Error),
    Step(StepError),
}

#[derive(Debug)]
pub enum StepError {
    TokenTooLong,
    InvalidHandle,
    InvalidToken,
    InsufficientMemory,
    LogonFailed,
}
