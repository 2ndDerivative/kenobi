use std::{ffi::c_void, fmt::Debug, slice, sync::LazyLock};

use windows::Win32::Security::Authentication::Identity::{
    FreeContextBuffer, QuerySecurityPackageInfoW, SECBUFFER_TOKEN, SECBUFFER_VERSION, SecBufferDesc,
};

use crate::NEGOTIATE;

static MAX_BUFFER_SIZE: LazyLock<windows_result::Result<u32>> = LazyLock::new(get_max_buffer_size);
fn get_max_buffer_size() -> windows_result::Result<u32> {
    let buf = unsafe { QuerySecurityPackageInfoW(NEGOTIATE)? };
    let size = unsafe { (*buf).cbMaxToken };
    unsafe { FreeContextBuffer(buf as *mut c_void)? };
    Ok(size)
}

#[repr(C)]
#[derive(Debug)]
pub struct RustSecBuffer {
    size: u32,
    pub(crate) buffer_type: u32,
    ptr: *mut c_void,
}
impl RustSecBuffer {
    pub fn new_for_token() -> windows_result::Result<Self> {
        let size = MAX_BUFFER_SIZE.clone()?;
        Ok(Self::new_with_size(SECBUFFER_TOKEN, size))
    }
    fn new_with_size(r#type: u32, size: u32) -> Self {
        let zeroed: Box<[u8]> = unsafe { Box::new_zeroed_slice(size as usize).assume_init() };
        let b: *mut [u8] = Box::into_raw(zeroed);
        RustSecBuffer {
            size,
            buffer_type: r#type,
            ptr: b as *mut c_void,
        }
    }
    pub fn reformat_as_input(&mut self) {
        self.size = MAX_BUFFER_SIZE.clone().unwrap();
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr as *mut u8, self.size as usize) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr as *mut u8, self.size as usize) }
    }
}

impl Drop for RustSecBuffer {
    fn drop(&mut self) {
        let arr = self.as_mut_slice();
        drop(unsafe { Box::from_raw(arr) });
    }
}
unsafe impl Sync for RustSecBuffer {}
unsafe impl Send for RustSecBuffer {}

#[repr(C)]
pub struct RustSecBuffers {
    version: u32,
    count: u32,
    ptr: *mut RustSecBuffer,
}
impl RustSecBuffers {
    pub fn new(buffers: Box<[RustSecBuffer]>) -> Self {
        let ptr = Box::leak(buffers);
        let count = ptr.len() as u32;
        let ptr = ptr.as_mut_ptr();
        RustSecBuffers {
            version: SECBUFFER_VERSION,
            count,
            ptr,
        }
    }
    pub fn as_slice(&self) -> &[RustSecBuffer] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.count as usize) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [RustSecBuffer] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.count as usize) }
    }

    pub fn as_windows_ptr(&mut self) -> *mut SecBufferDesc {
        unsafe { std::mem::transmute::<&mut RustSecBuffers, &mut SecBufferDesc>(self) }
    }
}
impl Debug for RustSecBuffers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_list();
        for entry in self.as_slice() {
            l.entry(entry);
        }
        l.finish()
    }
}
impl Drop for RustSecBuffers {
    fn drop(&mut self) {
        let arr = self.as_mut_slice();
        drop(unsafe { Box::from_raw(arr) });
    }
}
unsafe impl Sync for RustSecBuffers {}
unsafe impl Send for RustSecBuffers {}
