#![allow(dead_code)]

use std::{
    error::Error,
    ffi::CStr,
    fmt::Debug,
    ops::{
        Deref,
        DerefMut,
    },
    sync::{
        Arc,
        Weak,
    },
};

use anyhow::Context;
use obfstr::obfstr;
use raw_struct::{
    FromMemoryView,
    MemoryView,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};
use valthrun_driver_interface::{
    DirectoryTableType,
    DriverFeature,
    DriverInterface,
    InterfaceError,
    KeyboardState,
    MouseState,
    ProcessId,
    ProcessModuleInfo,
    ProcessProtectionMode,
};

use crate::{
    SearchPattern,
    Signature,
    SignatureType,
};

struct PubgMemoryView {
    handle: Weak<PubgHandle>,
}

impl MemoryView for PubgMemoryView {
    fn read_memory(
        &self,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let Some(handle) = self.handle.upgrade() else {
            return Err(anyhow::anyhow!("Pubg handle gone").into());
        };

        Ok(handle.read_slice(offset, buffer)?)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Module {
    Game,
}

impl Module {
    fn get_module_name(&self) -> &'static str {
        match self {
            Module::Game => "TslGame.exe",
        }
    }
}

/// Handle to the Pubg process
pub struct PubgHandle {
    weak_self: Weak<Self>,
    metrics: bool,

    modules: Vec<ProcessModuleInfo>,
    process_id: ProcessId,

    pub ke_interface: DriverInterface,
}

struct ModRmInfo {
    mode: u8,
    rm: u8,
    rex_b: bool,
    disp: u64,
    has_disp: bool,
    rip_relative: bool,
}

impl PubgHandle {
    fn dump_matched_bytes(&self, signature: &Signature, inst_offset: u64) {
        let match_len = signature.pattern.length();
        if match_len == 0 {
            return;
        }
        let mut match_buf = vec![0u8; match_len];
        if let Err(err) = self.ke_interface.read_slice(
            self.process_id,
            DirectoryTableType::Default,
            inst_offset,
            &mut match_buf,
        ) {
            log::debug!(
                "failed to read matched bytes for '{}' at {:#x}: {}",
                signature.debug_name,
                inst_offset,
                err
            );
            return;
        }
        let hex = match_buf
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        log::debug!("matched bytes for '{}': {}", signature.debug_name, hex);
    }
    fn read_modrm_based_displacement(&self, inst_offset: u64) -> anyhow::Result<u64> {
        // Read enough bytes for REX + opcode + ModRM + optional SIB + disp32
        let mut buf = [0u8; 16];
        self.ke_interface.read_slice(
            self.process_id,
            DirectoryTableType::Default,
            inst_offset,
            &mut buf,
        )?;

        // Assume single REX prefix at inst_offset as in our patterns
        let mut idx = 0usize;
        let rex = buf[idx];
        if rex < 0x40 || rex > 0x4F {
            // No REX prefix; treat current byte as opcode
        } else {
            idx += 1;
        }

        if idx >= buf.len() {
            anyhow::bail!("decode: truncated before opcode")
        }
        let opcode = buf[idx];
        idx += 1;
        // We only support MOV r64, r/m64 (0x8B) style for offsets
        if opcode != 0x8B {
            anyhow::bail!(
                "decode: unsupported opcode {:02X} at {:#x}",
                opcode,
                inst_offset + (idx as u64 - 1)
            );
        }

        if idx >= buf.len() {
            anyhow::bail!("decode: truncated before ModRM")
        }
        let modrm = buf[idx];
        idx += 1;
        let mode = (modrm & 0xC0) >> 6; // 00,01,10,11
        let rm = modrm & 0x07;

        // Optional SIB byte when r/m == 100
        if rm == 0b100 {
            // SIB present
            if idx >= buf.len() {
                anyhow::bail!("decode: truncated before SIB")
            }
            let _sib = buf[idx];
            idx += 1;
        }

        let disp_size: usize = match mode {
            0b01 => 1, // disp8
            0b10 => 4, // disp32
            0b00 => {
                // No displacement (except RIP-relative when rm==101, but that's not a struct offset)
                0
            }
            _ => 0, // register-direct, no displacement
        };

        if disp_size == 0 {
            return Ok(0);
        }

        if idx + disp_size > buf.len() {
            anyhow::bail!("decode: truncated displacement")
        }
        let disp = match disp_size {
            1 => buf[idx] as u64,
            4 => {
                let b = &buf[idx..idx + 4];
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
            }
            _ => 0,
        };

        Ok(disp)
    }

    fn decode_modrm_info(&self, inst_offset: u64) -> anyhow::Result<ModRmInfo> {
        let mut buf = [0u8; 16];
        self.ke_interface.read_slice(
            self.process_id,
            DirectoryTableType::Default,
            inst_offset,
            &mut buf,
        )?;

        let mut idx = 0usize;
        let mut rex_b = false;
        if (0x40..=0x4F).contains(&buf[idx]) {
            let rex = buf[idx];
            rex_b = (rex & 0x01) != 0;
            idx += 1;
        }
        if idx >= buf.len() {
            anyhow::bail!("decode: truncated before opcode")
        }
        let opcode = buf[idx];
        idx += 1;
        if opcode != 0x8B {
            anyhow::bail!("decode: unsupported opcode {:02X}", opcode);
        }
        if idx >= buf.len() {
            anyhow::bail!("decode: truncated before ModRM")
        }
        let modrm = buf[idx];
        idx += 1;
        let mode = (modrm & 0xC0) >> 6;
        let rm = modrm & 0x07;
        if rm == 0b100 {
            // SIB present (ignored here)
            if idx >= buf.len() {
                anyhow::bail!("decode: truncated before SIB")
            }
            idx += 1;
        }
        let (has_disp, disp_size) = match mode {
            0b01 => (true, 1usize),
            0b10 => (true, 4usize),
            0b00 => (false, 0usize),
            _ => (false, 0usize),
        };
        let mut disp = 0u64;
        if has_disp {
            if idx + disp_size > buf.len() {
                anyhow::bail!("decode: truncated displacement")
            }
            if disp_size == 1 {
                disp = buf[idx] as u64;
            } else {
                let b = &buf[idx..idx + 4];
                disp = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            }
        }
        let rip_relative = mode == 0 && rm == 0b101;
        Ok(ModRmInfo {
            mode,
            rm,
            rex_b,
            disp,
            has_disp,
            rip_relative,
        })
    }

    pub fn resolve_signature_struct_offset_resilient(
        &self,
        module: Module,
        signature: &Signature,
        require_rax_base: bool,
        select_last: bool,
    ) -> anyhow::Result<Option<u64>> {
        let module_info = self.get_module_info(module).with_context(|| {
            format!("{} {}", obfstr!("missing module"), module.get_module_name())
        })?;
        let mut cursor = module_info.base_address;
        let end = module_info.base_address + module_info.module_size as u64;
        let mut found_value: Option<u64> = None;
        while cursor < end {
            let length = (end - cursor) as usize;
            let Some(inst_offset) =
                self.find_pattern_resilient(cursor, length, &*signature.pattern)?
            else {
                break;
            };
            // Validate instruction
            let ok = match self.decode_modrm_info(inst_offset) {
                Ok(info) => {
                    if info.rip_relative || !info.has_disp {
                        false
                    } else if require_rax_base {
                        info.rm == 0 && !info.rex_b
                    } else {
                        true
                    }
                }
                Err(_) => false,
            };
            if ok {
                let info = self.decode_modrm_info(inst_offset).ok();
                if let Some(info) = info {
                    if select_last {
                        found_value = Some(info.disp);
                    } else {
                        return Ok(Some(info.disp));
                    }
                }
            }
            cursor = inst_offset + 1;
        }
        Ok(found_value)
    }
    pub fn create(metrics: bool) -> anyhow::Result<Arc<Self>> {
        let interface = DriverInterface::create_from_env()?;

        if interface
            .driver_features()
            .contains(DriverFeature::ProcessProtectionKernel)
        {
            /*
             * Please no not analyze me:
             * https://www.unknowncheats.me/wiki/Valve_Anti-Cheat:VAC_external_tool_detection_(and_more)
             *
             * Even tough we don't have open handles to Pubg we don't want anybody to read our process.
             */
            if let Err(err) = interface.toggle_process_protection(ProcessProtectionMode::Kernel) {
                log::warn!("Failed to enable process protection: {}", err)
            };
        }

        let driver_name = interface
            .driver_version()
            .get_application_name()
            .unwrap_or("<invalid>");

        if driver_name != obfstr!("zenith-driver") {
            return Err(InterfaceError::NotZenithDriver.into());
        }

        let process = interface
            .list_processes()?
            .into_iter()
            .filter(|process| {
                process.get_image_base_name().unwrap_or_default() == obfstr!("TslGame.exe")
            })
            .collect::<Vec<_>>();
        let process = if process.is_empty() {
            return Err(InterfaceError::ProcessUnknown.into());
        } else {
            process.last().unwrap()
        };

        let modules = interface.list_modules(process.process_id, DirectoryTableType::Default)?;
        log::debug!(
            "{}. Process id {}",
            obfstr!("Successfully initialized Pubg handle"),
            process.process_id
        );

        log::trace!("{} ({})", obfstr!("Pubg modules"), modules.len());
        for module in modules.iter() {
            log::trace!(
                "  - {} ({:X} - {:X})",
                module.get_base_dll_name().unwrap_or("unknown"),
                module.base_address,
                module.base_address + module.module_size
            );
        }

        Ok(Arc::new_cyclic(|weak_self| Self {
            weak_self: weak_self.clone(),
            metrics,
            modules,
            process_id: process.process_id,

            ke_interface: interface,
        }))
    }

    fn get_module_info(&self, target: Module) -> Option<&ProcessModuleInfo> {
        self.modules
            .iter()
            .find(|module| module.get_base_dll_name() == Some(target.get_module_name()))
    }

    pub fn process_id(&self) -> ProcessId {
        self.process_id
    }

    pub fn send_keyboard_state(&self, states: &[KeyboardState]) -> anyhow::Result<()> {
        self.ke_interface.send_keyboard_state(states)?;
        Ok(())
    }

    pub fn send_mouse_state(&self, states: &[MouseState]) -> anyhow::Result<()> {
        self.ke_interface.send_mouse_state(states)?;
        Ok(())
    }

    pub fn add_metrics_record(&self, record_type: &str, record_payload: &str) {
        if !self.metrics {
            /* user opted out */
            return;
        }

        let _ = self
            .ke_interface
            .add_metrics_record(record_type, record_payload);
    }

    pub fn module_address(&self, module: Module, address: u64) -> Option<u64> {
        let module = self.get_module_info(module)?;
        if address < module.base_address || address >= (module.base_address + module.module_size) {
            None
        } else {
            Some(address - module.base_address)
        }
    }

    pub fn memory_address(&self, module: Module, offset: u64) -> anyhow::Result<u64> {
        Ok(self
            .get_module_info(module)
            .with_context(|| format!("{} {}", obfstr!("missing module"), module.get_module_name()))?
            .base_address as u64
            + offset)
    }

    pub fn module_size(&self, module: Module) -> anyhow::Result<u64> {
        Ok(self
            .get_module_info(module)
            .with_context(|| format!("{} {}", obfstr!("missing module"), module.get_module_name()))?
            .module_size)
    }

    pub fn read_sized<T: Copy>(&self, address: u64) -> anyhow::Result<T> {
        Ok(self
            .ke_interface
            .read(self.process_id, DirectoryTableType::Default, address)?)
    }

    pub fn read_slice<T: Copy>(&self, address: u64, buffer: &mut [T]) -> anyhow::Result<()> {
        Ok(self.ke_interface.read_slice(
            self.process_id,
            DirectoryTableType::Default,
            address,
            buffer,
        )?)
    }

    pub fn read_string(
        &self,
        address: u64,
        expected_length: Option<usize>,
    ) -> anyhow::Result<String> {
        let mut expected_length = expected_length.unwrap_or(8); // Using 8 as we don't know how far we can read
        let mut buffer = Vec::new();

        // FIXME: Do cstring reading within the kernel driver!
        loop {
            buffer.resize(expected_length, 0u8);
            self.read_slice(address, buffer.as_mut_slice())
                .context("read_string")?;

            if let Ok(str) = CStr::from_bytes_until_nul(&buffer) {
                return Ok(str.to_str().context("invalid string contents")?.to_string());
            }

            expected_length += 8;
        }
    }

    pub fn create_memory_view(&self) -> Arc<dyn MemoryView + Send + Sync> {
        Arc::new(PubgMemoryView {
            handle: self.weak_self.clone(),
        })
    }

    #[must_use]
    pub fn find_pattern(
        &self,
        address: u64,
        length: usize,
        pattern: &dyn SearchPattern,
    ) -> anyhow::Result<Option<u64>> {
        if pattern.length() > length {
            return Ok(None);
        }

        let mut buffer = Vec::<u8>::with_capacity(length);
        buffer.resize(length, 0);
        self.ke_interface.read_slice(
            self.process_id,
            DirectoryTableType::Default,
            address,
            &mut buffer,
        )?;

        for (index, window) in buffer.windows(pattern.length()).enumerate() {
            if !pattern.is_matching(window) {
                continue;
            }

            return Ok(Some(address + index as u64));
        }

        Ok(None)
    }

    /// Like find_pattern but skips pages/chunks that cannot be read (e.g., paged out).
    /// Scans in chunks with overlap so matches spanning chunk boundaries are still found.
    pub fn find_pattern_resilient(
        &self,
        address: u64,
        length: usize,
        pattern: &dyn SearchPattern,
    ) -> anyhow::Result<Option<u64>> {
        if pattern.length() > length {
            return Ok(None);
        }

        const CHUNK_SIZE: usize = 0x10000; // 64 KiB chunks
        let overlap = pattern.length().saturating_sub(1);
        let mut prev_tail: Vec<u8> = Vec::new();

        let mut processed: usize = 0;
        while processed < length {
            let to_read = CHUNK_SIZE.min(length - processed);
            let mut chunk = vec![0u8; to_read];
            let read_addr = address + processed as u64;
            match self.ke_interface.read_slice(
                self.process_id,
                DirectoryTableType::Default,
                read_addr,
                &mut chunk,
            ) {
                Ok(()) => {
                    // build scan buffer with overlap from previous chunk
                    let mut scan_buf = Vec::with_capacity(prev_tail.len() + chunk.len());
                    scan_buf.extend_from_slice(&prev_tail);
                    scan_buf.extend_from_slice(&chunk);

                    for (index, window) in scan_buf.windows(pattern.length()).enumerate() {
                        if !pattern.is_matching(window) {
                            continue;
                        }
                        let global_offset = (processed as isize - (prev_tail.len() as isize)
                            + (index as isize)) as u64;
                        return Ok(Some(address + global_offset));
                    }

                    // update prev tail for next overlap
                    if overlap > 0 {
                        let take = overlap.min(chunk.len());
                        prev_tail.clear();
                        prev_tail.extend_from_slice(&chunk[chunk.len() - take..]);
                    } else {
                        prev_tail.clear();
                    }
                }
                Err(_err) => {
                    // Skip unreadable region (likely paged out). Reset overlap continuity.
                    prev_tail.clear();
                }
            }

            processed += to_read;
        }

        Ok(None)
    }

    /// Resilient scan that returns the last match in the given range, skipping unreadable pages.
    pub fn find_pattern_resilient_last(
        &self,
        address: u64,
        length: usize,
        pattern: &dyn SearchPattern,
    ) -> anyhow::Result<Option<u64>> {
        if pattern.length() > length {
            return Ok(None);
        }

        const CHUNK_SIZE: usize = 0x10000; // 64 KiB chunks
        let overlap = pattern.length().saturating_sub(1);
        let mut prev_tail: Vec<u8> = Vec::new();

        let mut processed: usize = 0;
        let mut last_match: Option<u64> = None;
        while processed < length {
            let to_read = CHUNK_SIZE.min(length - processed);
            let mut chunk = vec![0u8; to_read];
            let read_addr = address + processed as u64;
            match self.ke_interface.read_slice(
                self.process_id,
                DirectoryTableType::Default,
                read_addr,
                &mut chunk,
            ) {
                Ok(()) => {
                    let mut scan_buf = Vec::with_capacity(prev_tail.len() + chunk.len());
                    scan_buf.extend_from_slice(&prev_tail);
                    scan_buf.extend_from_slice(&chunk);

                    for (index, window) in scan_buf.windows(pattern.length()).enumerate() {
                        if !pattern.is_matching(window) {
                            continue;
                        }
                        let global_offset = (processed as isize - (prev_tail.len() as isize)
                            + (index as isize)) as u64;
                        last_match = Some(address + global_offset);
                    }

                    if overlap > 0 {
                        let take = overlap.min(chunk.len());
                        prev_tail.clear();
                        prev_tail.extend_from_slice(&chunk[chunk.len() - take..]);
                    } else {
                        prev_tail.clear();
                    }
                }
                Err(_err) => {
                    prev_tail.clear();
                }
            }

            processed += to_read;
        }

        Ok(last_match)
    }

    pub fn resolve_signature(&self, module: Module, signature: &Signature) -> anyhow::Result<u64> {
        log::trace!("Resolving '{}' in {:?}", signature.debug_name, module);
        let module_info = self.get_module_info(module).with_context(|| {
            format!("{} {}", obfstr!("missing module"), module.get_module_name())
        })?;
        log::debug!(
            "resolve_signature '{}' module base={:#x} size={:#x}",
            signature.debug_name,
            module_info.base_address,
            module_info.module_size
        );

        let search_start = module_info.base_address;
        let search_end = module_info.base_address + module_info.module_size;
        let pattern_len = signature.pattern.length();
        log::debug!(
            "searching pattern len {} in [{:#x}..{:#x})",
            pattern_len,
            search_start,
            search_end
        );

        let inst_offset = self
            .find_pattern(
                module_info.base_address,
                module_info.module_size as usize,
                &*signature.pattern,
            )
            .map_err(|err| {
                log::error!(
                    "pattern search failed for '{}' in [{:#x}..{:#x}): {}",
                    signature.debug_name,
                    search_start,
                    search_end,
                    err
                );
                err
            })?
            .with_context(|| {
                format!(
                    "{} {}",
                    obfstr!("failed to find pattern"),
                    signature.debug_name
                )
            })?;
        log::debug!(
            "pattern '{}' found at inst_offset={:#x} (RVA {:#x})",
            signature.debug_name,
            inst_offset,
            self.module_address(module, inst_offset).unwrap_or(u64::MAX)
        );

        self.dump_matched_bytes(signature, inst_offset);

        let read_addr = inst_offset + signature.offset;
        log::debug!(
            "reading u32 for '{}' at {:#x} (inst_offset {:#x} + offset {:#x})",
            signature.debug_name,
            read_addr,
            inst_offset,
            signature.offset
        );
        let value_raw = u32::read_object(&*self.create_memory_view(), read_addr).map_err(|err| {
            anyhow::anyhow!(
                "reading u32 at {:#x} for '{}' failed: {}",
                read_addr,
                signature.debug_name,
                err
            )
        })? as u64;
        let value = match &signature.value_type {
            SignatureType::Offset => {
                // Some patterns indicate MOV r64, [r/m64 + disp], so the field offset is ModRM displacement.
                // Try to decode ModRM-based disp and prefer it if non-zero and sane.
                match self.read_modrm_based_displacement(inst_offset) {
                    Ok(disp) if disp != 0 && disp < 0x10000 => disp,
                    _ => value_raw,
                }
            }
            SignatureType::RelativeAddress { inst_length } => inst_offset + value_raw + inst_length,
        };

        match &signature.value_type {
            SignatureType::Offset => log::trace!(
                " => {:X} (inst at {:X})",
                value,
                self.module_address(module, inst_offset).unwrap_or(u64::MAX)
            ),
            SignatureType::RelativeAddress { .. } => log::trace!(
                "  => {:X} ({:X})",
                value,
                self.module_address(module, value).unwrap_or(u64::MAX)
            ),
        }

        Ok(value)
    }

    /// Resolve a signature while skipping unreadable pages during the pattern search.
    /// Returns Ok(None) if the pattern cannot be found.
    pub fn resolve_signature_resilient(
        &self,
        module: Module,
        signature: &Signature,
    ) -> anyhow::Result<Option<u64>> {
        log::trace!(
            "Resolving (resilient) '{}' in {:?}",
            signature.debug_name,
            module
        );
        let module_info = self.get_module_info(module).with_context(|| {
            format!("{} {}", obfstr!("missing module"), module.get_module_name())
        })?;

        let inst_offset = match self.find_pattern_resilient(
            module_info.base_address,
            module_info.module_size as usize,
            &*signature.pattern,
        )? {
            Some(off) => off,
            None => return Ok(None),
        };

        self.dump_matched_bytes(signature, inst_offset);

        let value = u32::read_object(&*self.create_memory_view(), inst_offset + signature.offset)
            .map_err(|err| {
                anyhow::anyhow!(
                    "reading u32 at {:#x} for '{}' failed: {}",
                    inst_offset + signature.offset,
                    signature.debug_name,
                    err
                )
            })? as u64;

        let value = match &signature.value_type {
            SignatureType::Offset => match self.read_modrm_based_displacement(inst_offset) {
                Ok(disp) if disp != 0 && disp < 0x10000 => disp,
                _ => value,
            },
            SignatureType::RelativeAddress { inst_length } => inst_offset + value + inst_length,
        };

        Ok(Some(value))
    }

    /// Resolve a signature using last occurrence of the pattern, while skipping unreadable pages.
    pub fn resolve_signature_resilient_last(
        &self,
        module: Module,
        signature: &Signature,
    ) -> anyhow::Result<Option<u64>> {
        log::trace!(
            "Resolving (resilient last) '{}' in {:?}",
            signature.debug_name,
            module
        );
        let module_info = self.get_module_info(module).with_context(|| {
            format!("{} {}", obfstr!("missing module"), module.get_module_name())
        })?;

        let inst_offset = match self.find_pattern_resilient_last(
            module_info.base_address,
            module_info.module_size as usize,
            &*signature.pattern,
        )? {
            Some(off) => off,
            None => return Ok(None),
        };

        self.dump_matched_bytes(signature, inst_offset);

        let value = u32::read_object(&*self.create_memory_view(), inst_offset + signature.offset)
            .map_err(|err| {
                anyhow::anyhow!(
                    "reading u32 at {:#x} for '{}' failed: {}",
                    inst_offset + signature.offset,
                    signature.debug_name,
                    err
                )
            })? as u64;

        let value = match &signature.value_type {
            SignatureType::Offset => match self.read_modrm_based_displacement(inst_offset) {
                Ok(disp) if disp != 0 && disp < 0x10000 => disp,
                _ => value,
            },
            SignatureType::RelativeAddress { inst_length } => inst_offset + value + inst_length,
        };

        Ok(Some(value))
    }
}

pub struct StateVariable<T: 'static + Send + Sync>(T);

impl<T: 'static + Send + Sync> StateVariable<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn value(&self) -> &T {
        &self.0
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: 'static + Send + Sync> State for StateVariable<T> {
    type Parameter = ();

    fn create(_states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        anyhow::bail!("StateVariable must be manually set")
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Persistent
    }
}

impl<T: 'static + Send + Sync> Deref for StateVariable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
}

impl<T: 'static + Send + Sync> DerefMut for StateVariable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value_mut()
    }
}

pub type StatePubgHandle = StateVariable<Arc<PubgHandle>>;
pub type StatePubgMemory = StateVariable<Arc<dyn MemoryView + Send + Sync>>;

impl StatePubgMemory {
    pub fn view_arc(&self) -> Arc<dyn MemoryView> {
        self.value().clone()
    }

    pub fn view(&self) -> &dyn MemoryView {
        &**self.value()
    }
}
