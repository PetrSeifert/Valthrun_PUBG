#[cfg(target_os = "linux")]
use std::ptr;
use std::{
    io,
    mem::transmute,
};

use anyhow::anyhow;
#[cfg(target_os = "linux")]
use libc::{
    mmap,
    MAP_ANONYMOUS,
    MAP_PRIVATE,
    PROT_EXEC,
    PROT_READ,
    PROT_WRITE,
};
use raw_struct::{
    AccessError,
    AccessMode,
    FromMemoryView,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc,
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE,
};

use crate::{
    Module,
    StatePubgHandle,
    StatePubgMemory,
};

#[cfg(target_os = "windows")]
type XenuineDecrypt = unsafe extern "fastcall" fn(u64, u64) -> u64;

#[cfg(target_os = "linux")]
type XenuineDecrypt = unsafe extern "win64" fn(u64, u64) -> u64;

pub const DECRYPT_OFFSET: u64 = 0x0F2F5F28; // XenuineDecrypt

pub struct StateDecrypt {
    decrypt_key: u64,
    xenuine_decrypt_fn: XenuineDecrypt,
}

#[cfg(target_os = "linux")]
fn allocate_executable_memory(size: usize) -> Result<*mut u8, io::Error> {
    unsafe {
        let addr = mmap(
            ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to allocate executable memory with mmap: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }

        Ok(addr as *mut u8)
    }
}

#[cfg(target_os = "windows")]
fn allocate_executable_memory(size: usize) -> Result<*mut u8, io::Error> {
    unsafe {
        let addr = VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        if addr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to allocate executable memory with VirtualAlloc",
            ));
        }

        Ok(addr as *mut u8)
    }
}

impl State for StateDecrypt {
    type Parameter = ();

    fn create(_states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        unsafe {
            let pubg_handle = _states.resolve::<StatePubgHandle>(())?;
            let memory = _states.resolve::<StatePubgMemory>(())?;
            let decrypt_ptr = u64::read_object(
                memory.view(),
                pubg_handle.memory_address(Module::Game, DECRYPT_OFFSET)?,
            )
            .map_err(|err| anyhow::anyhow!("{}", err))? as u64;
            let tmp1_add = i32::read_object(memory.view(), decrypt_ptr + 3)
                .map_err(|err| anyhow::anyhow!("{}", err))? as u64;
            let decrypt_key = tmp1_add + decrypt_ptr + 7;

            let mut code_buff: [u8; 1024] = [0; 1024];
            code_buff[0] = 0x90;
            code_buff[1] = 0x90;
            memory
                .read_memory(decrypt_ptr, &mut code_buff[2..])
                .map_err(|err| AccessError {
                    source: err,

                    mode: AccessMode::Read,
                    offset: decrypt_ptr,
                    size: 1022,

                    member: None,
                    object: "unknown".into(),
                })?;
            code_buff[2] = 0x48;
            code_buff[3] = 0x8B;
            code_buff[4] = 0xC1;
            code_buff[5] = 0x90;
            code_buff[6] = 0x90;
            code_buff[7] = 0x90;
            code_buff[8] = 0x90;

            let executable_memory = match allocate_executable_memory(code_buff.len() + 4) {
                Ok(mem) => mem,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to allocate executable memory for XenuineDecrypt function: {}",
                        e
                    ));
                }
            };

            std::ptr::copy_nonoverlapping(code_buff.as_ptr(), executable_memory, code_buff.len());

            let xenuine_decrypt_fn = transmute(executable_memory);

            Ok(Self {
                decrypt_key,
                xenuine_decrypt_fn,
            })
        }
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Volatile
    }
}

impl StateDecrypt {
    #[inline]
    pub unsafe fn decrypt(&self, a: u64) -> u64 {
        let result = (self.xenuine_decrypt_fn)(self.decrypt_key, a);
        result
    }

    #[inline]
    pub fn decrypt_c_index(value: u32) -> u32 {
        let v89 = value ^ (value << 16) ^ 0x49469D07;
        v89
    }
}
