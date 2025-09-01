use std::{ffi::c_void, marker::PhantomData, mem::ManuallyDrop};

use windows::{
    core::w,
    Win32::Security::Authentication::Identity::{
        FreeContextBuffer, QuerySecurityPackageInfoW, SecBuffer, SecBufferDesc, SECBUFFER_READONLY, SECBUFFER_TOKEN,
        SECBUFFER_VERSION,
    },
};

use crate::ServerSettings;

pub struct ReadOnlySecBuffer<'ro> {
    _lifetime: PhantomData<&'ro [u8]>,
    buffer: SecBuffer,
}
impl<'ro> ReadOnlySecBuffer<'ro> {
    pub fn from_slice(ro: &'ro [u8]) -> Result<ReadOnlySecBuffer<'ro>, TokenTooLong> {
        Ok(Self {
            _lifetime: PhantomData,
            buffer: SecBuffer {
                cbBuffer: ro.len().try_into().map_err(|_| TokenTooLong)?,
                BufferType: SECBUFFER_TOKEN | SECBUFFER_READONLY,
                pvBuffer: ro.as_ptr() as *mut c_void,
            },
        })
    }
    pub fn buffer_mut(&mut self) -> &mut SecBuffer {
        &mut self.buffer
    }
}

#[derive(Debug)]
pub struct TokenTooLong;

/// To join the drop glue for the buffers
pub struct MaybeAllocatedBuffer {
    settings: ServerSettings,
    buffers: SecurityBuffers,
}
impl MaybeAllocatedBuffer {
    pub fn new(settings: ServerSettings) -> Result<Self, windows::core::Error> {
        let buffers = if settings.lets_sspi_allocate() {
            SecurityBuffers {
                from_sspi: ManuallyDrop::new(SspiAllocatedSecurityBuffers(SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: 0,
                    pBuffers: std::ptr::null_mut(),
                })),
            }
        } else {
            let package_info = unsafe { QuerySecurityPackageInfoW(w!("Negotiate"))?.as_mut() }.unwrap();
            let token_size = package_info.cbMaxToken as usize;
            let _ = unsafe { FreeContextBuffer(std::ptr::from_mut(package_info).cast()) };
            let token_allocation: Box<[u8]> = vec![0; token_size].into_boxed_slice();
            let token_buffer = SecBuffer {
                cbBuffer: token_allocation.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: Box::into_raw(token_allocation).cast(),
            };
            SecurityBuffers {
                self_allocated: ManuallyDrop::new(OwnedSecurityBuffers(Box::new([token_buffer]))),
            }
        };
        Ok(Self { settings, buffers })
    }
    pub fn server_settings(&self) -> ServerSettings {
        self.settings
    }
    pub fn as_desc(&mut self) -> SecBufferDesc {
        if self.settings.lets_sspi_allocate() {
            unsafe { self.buffers.from_sspi.0 }
        } else {
            let buf = unsafe { &mut self.buffers.self_allocated };
            let boxed_slice = &mut buf.0;
            SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: boxed_slice.len() as u32,
                pBuffers: boxed_slice.as_mut_ptr(),
            }
        }
    }
}
impl Drop for MaybeAllocatedBuffer {
    fn drop(&mut self) {
        if self.settings.lets_sspi_allocate() {
            unsafe { ManuallyDrop::drop(&mut self.buffers.from_sspi) }
        } else {
            let array = unsafe { ManuallyDrop::take(&mut self.buffers.self_allocated).0 };
            for SecBuffer { cbBuffer, pvBuffer, .. } in array {
                let sec_buffer_array =
                    unsafe { Vec::from_raw_parts(pvBuffer, cbBuffer as usize, cbBuffer as usize) }.into_boxed_slice();
                drop(sec_buffer_array);
            }
        }
    }
}

union SecurityBuffers {
    self_allocated: ManuallyDrop<OwnedSecurityBuffers>,
    from_sspi: ManuallyDrop<SspiAllocatedSecurityBuffers>,
}

pub struct OwnedSecurityBuffers(Box<[SecBuffer]>);

pub struct SspiAllocatedSecurityBuffers(SecBufferDesc);
impl Drop for SspiAllocatedSecurityBuffers {
    fn drop(&mut self) {
        let array_pointer = self.0.pBuffers;
        if !array_pointer.is_null() {
            unsafe {
                let arr = std::slice::from_raw_parts_mut(array_pointer, self.0.cBuffers as usize);
                for buffer in arr {
                    if !buffer.pvBuffer.is_null() {
                        let _ = FreeContextBuffer(buffer.pvBuffer.cast());
                    }
                }
                let _ = FreeContextBuffer(array_pointer.cast());
            }
        }
    }
}
