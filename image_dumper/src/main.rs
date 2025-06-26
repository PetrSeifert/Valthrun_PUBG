use std::{
    fs::File,
    io::Write,
    mem,
};

use obfstr::obfstr;
use pubg::{
    InterfaceError,
    Module,
    PubgHandle,
    StatePubgHandle,
    StatePubgMemory,
};
use utils_console::show_critical_error;
use utils_state::StateRegistry;

// PE header structures
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,      // Magic number
    _unused: [u8; 58], // Rest of DOS header we don't need
    e_lfanew: u32,     // File address of new exe header
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageOptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    // Data directories follow but we don't need them
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageNtHeaders {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    misc_virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE00"

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    if let Err(err) = real_main() {
        show_critical_error(&format!("{:#}", err));
    }
}

fn real_main() -> anyhow::Result<()> {
    log::info!(
        "{} v{} ({})",
        obfstr!("Pubg_Valthrun-image-dumper"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH"),
    );
    log::info!("{} {}", obfstr!("Build time:"), env!("BUILD_TIME"));

    let pubg = match PubgHandle::create(false) {
        Ok(pubg) => pubg,
        Err(err) => {
            if let Some(err) = err.downcast_ref::<InterfaceError>() {
                if let Some(detailed_message) = err.detailed_message() {
                    show_critical_error(&detailed_message);
                    return Ok(());
                }
            }

            return Err(err);
        }
    };

    let mut states = StateRegistry::new(1024 * 8);
    states.set(StatePubgHandle::new(pubg.clone()), ())?;
    states.set(StatePubgMemory::new(pubg.create_memory_view()), ())?;

    log::info!("Initialized.");

    let memory = states.resolve::<StatePubgMemory>(())?;
    let handle = states.resolve::<StatePubgHandle>(())?;

    let module_address = handle.memory_address(Module::Game, 0x0)?;
    log::info!("Module address: {:#x}", module_address);

    // Read the PE headers (first 0x1000 bytes)
    const HEADER_SIZE: usize = 0x1000;
    let mut header_buffer = vec![0u8; HEADER_SIZE];
    memory
        .read_memory(module_address, &mut header_buffer)
        .map_err(|e| anyhow::anyhow!("Failed to read PE headers: {}", e))?;
    log::info!("Read PE headers ({} bytes)", HEADER_SIZE);

    // Parse DOS header
    let dos_header = unsafe { &*(header_buffer.as_ptr() as *const ImageDosHeader) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow::anyhow!(
            "Invalid DOS signature: {:#x}",
            dos_header.e_magic
        ));
    }
    log::info!(
        "DOS header valid, NT headers offset: {:#x}",
        dos_header.e_lfanew
    );

    // Parse NT headers
    let nt_headers_offset = dos_header.e_lfanew as usize;
    if nt_headers_offset >= HEADER_SIZE {
        return Err(anyhow::anyhow!(
            "NT headers offset too large: {:#x}",
            nt_headers_offset
        ));
    }

    let nt_headers =
        unsafe { &*(header_buffer.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders) };
    if nt_headers.signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow::anyhow!(
            "Invalid NT signature: {:#x}",
            nt_headers.signature
        ));
    }

    let image_size = nt_headers.optional_header.size_of_image as usize;
    log::info!(
        "Image size from PE headers: {:#x} ({} bytes)",
        image_size,
        image_size
    );

    let mut image_buffer = vec![0u8; image_size];

    // Read the image in 0x1000 byte chunks
    const CHUNK_SIZE: usize = 0x1000;
    let num_chunks = (image_size + CHUNK_SIZE - 1) / CHUNK_SIZE; // Round up division

    for chunk_index in 0..num_chunks {
        let offset = chunk_index * CHUNK_SIZE;
        let remaining = image_size - offset;
        let chunk_size = remaining.min(CHUNK_SIZE);

        if chunk_index % 100 == 0 {
            log::info!(
                "Reading chunk {}/{} (offset {:#x}, size {:#x})",
                chunk_index + 1,
                num_chunks,
                offset,
                chunk_size
            );
        }

        match memory.read_memory(
            module_address + offset as u64,
            &mut image_buffer[offset..offset + chunk_size],
        ) {
            Ok(()) => {
                // Successfully read this chunk
            }
            Err(err) => {
                log::warn!(
                    "Failed to read chunk {} at offset {:#x}: {}",
                    chunk_index,
                    offset,
                    err
                );
                // Continue with other chunks - some memory regions might be unreadable
            }
        }
    }

    log::info!("Fixing PE headers for memory dump...");
    fix_pe_headers(&mut image_buffer)?;

    let output_filename = "tslgame_dump.exe";
    let mut file = File::create(output_filename)?;
    file.write_all(&image_buffer)?;

    log::info!("Memory dump saved to: {}", output_filename);
    log::info!("Done");
    Ok(())
}

/// Fix PE headers to convert from memory layout to file layout
fn fix_pe_headers(buffer: &mut [u8]) -> anyhow::Result<()> {
    // Parse DOS header
    let dos_header = unsafe { &*(buffer.as_ptr() as *const ImageDosHeader) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow::anyhow!("Invalid DOS signature in buffer"));
    }

    // Parse NT headers
    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_headers =
        unsafe { &mut *(buffer.as_mut_ptr().add(nt_headers_offset) as *mut ImageNtHeaders) };
    if nt_headers.signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow::anyhow!("Invalid NT signature in buffer"));
    }

    let number_of_sections = nt_headers.file_header.number_of_sections as usize;
    log::info!("Fixing {} sections", number_of_sections);

    // Calculate section headers offset
    let section_headers_offset = nt_headers_offset + mem::size_of::<ImageNtHeaders>();

    // Fix each section header
    for i in 0..number_of_sections {
        let section_offset = section_headers_offset + (i * mem::size_of::<ImageSectionHeader>());
        if section_offset + mem::size_of::<ImageSectionHeader>() > buffer.len() {
            log::warn!("Section {} header extends beyond buffer", i);
            continue;
        }

        let section_header =
            unsafe { &mut *(buffer.as_mut_ptr().add(section_offset) as *mut ImageSectionHeader) };

        let section_name = String::from_utf8_lossy(&section_header.name)
            .trim_end_matches('\0')
            .to_string();

        log::debug!(
            "Section {}: {} - VirtAddr={:#x}, VirtSize={:#x}, RawPtr={:#x}, RawSize={:#x}",
            i,
            section_name,
            section_header.virtual_address,
            section_header.misc_virtual_size,
            section_header.pointer_to_raw_data,
            section_header.size_of_raw_data
        );

        // Fix the header: set PointerToRawData to VirtualAddress and SizeOfRawData to VirtualSize
        section_header.pointer_to_raw_data = section_header.virtual_address;
        section_header.size_of_raw_data = section_header.misc_virtual_size;

        log::debug!(
            "Fixed section {}: {} - RawPtr={:#x}, RawSize={:#x}",
            i,
            section_name,
            section_header.pointer_to_raw_data,
            section_header.size_of_raw_data
        );
    }

    log::info!("PE header fixing completed");
    Ok(())
}
