use std::fmt::Write;

use obfstr::obfstr;
use pubg::{
    InterfaceError,
    Module,
    PubgHandle,
    Signature,
    SignatureType,
    StatePubgHandle,
    StatePubgMemory,
};
use utils_common::get_os_info;
use utils_console::show_critical_error;
use utils_state::StateRegistry;

#[derive(Clone, Copy)]
enum SelectMode {
    First,
    Last,
}

struct SigEntry {
    spec: Signature,
    select: SelectMode,
}

fn main() {
    if std::env::var_os("RUST_LOG").is_some() {
        env_logger::Builder::from_default_env().init();
    } else {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    if let Err(err) = real_main() {
        show_critical_error(&format!("{:#}", err));
    }
}

fn real_main() -> anyhow::Result<()> {
    let build_info = get_os_info()?;
    let platform_info = if build_info.is_windows {
        format!("Windows build {}", build_info.build_number)
    } else {
        format!(
            "Linux kernel {}.{}.{}",
            build_info.major_version, build_info.minor_version, build_info.build_number
        )
    };
    log::info!(
        "{} v{} ({}). {}.",
        obfstr!("Pubg_Valthrun-offsets-dumper"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH"),
        platform_info
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

    let handle = states.resolve::<StatePubgHandle>(())?;

    let module_size = handle.module_size(Module::Game)? as usize;
    let module_address = handle.memory_address(Module::Game, 0x0)?;
    log::info!("Module size: {:#x}", module_size);
    log::info!("Module address: {:#x}", module_address);

    // Hardcoded signatures (subset of the provided list)
    let signatures: Vec<SigEntry> = vec![
        SigEntry {
            spec: Signature::relative_address(
                "Names",
                "48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E9 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? 48 83 3D ? ? ? ? ? 75 13 48 8B D1 B9 ? ? ? ? 48 8B 05 ? ? ? ? FF D0 EB 35",
                3,
                7,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::relative_address(
                "NamesOffset",
                "48 8D 0D ? ? ? ? 48 83 3D ? ? ? ? ? 75 ? 48 8B D1 B9 ? ? ? ?",
                3,
                7,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::relative_address(
                "GWorld",
                "48 89 05 ? ? ? ? 48 83 C4 28 C3 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? 48 8B 44 24 ? 48 89 05 ? ? ? ? 48 83 C4 28 C3",
                3,
                7,
            ),
            select: SelectMode::Last,
        },
        SigEntry {
            spec: Signature::offset(
                "CurrentLevel",
                "49 8B 56 50 4D 85 C0 75 0D 8B CE 48 8B 05 ? ? ? ? FF D0 EB 29",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset("GameInstance", "4C 8B ?? ? ? ? ? 4D 85 ?? 75 ??", 3),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset("LocalPlayers", "48 8B 86 ? ? ? ? 48 8B 0C D8 4D 85 C0", 3),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "Actors",
                "48 8B 88 ? ? ? ? 48 39 1D ? ? ? ? 75 13 48 8B D1 B9 ? ? ? ? 48 8B 05 ? ? ? ? FF D0 EB 38",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "PlayerCameraManager",
                "48 8B 88 ? ? ? ? 48 8B 01 FF 90 ? ? ? ? F3 41 0F 11 46 ? 48 83 3D ? ? ? ? ? 48 8B 0B",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "RootComponent",
                "4C 8B 97 ? ? ? ? 4D 85 C9 75 19 48 8B 05 ? ? ? ? 49 8B D2 B9 ? ? ? ? FF D0 48 8B C8 E9 ? ? ? ?",
                3,
            ),
            select: SelectMode::Last,
        },
        SigEntry {
            spec: Signature::offset(
                "CameraPos",
                "F2 0F 10 81 ? ? ? ? F2 0F 11 ?? 8B 81 ? ? ? ? 89 ?? 08 F2 0F 10 81 ? ? ? ?",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "CameraRot",
                "F2 0F 10 81 ? ? ? ? F2 0F 11 ?? 8B 81 ? ? ? ? 89 ?? 08 F2 0F 10 81 ? ? ? ?",
                24,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "CameraFov",
                "F3 0F 10 81 ? ? ? ? 0F 2F 05 ? ? ? ? 77 08 F3 0F 10 81 ? ? ? ?",
                4,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "bAlwaysCreatePhysicsState",
                "83 8F ? ? ? ? ? 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 20 5F C3",
                2,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "LastTeamNum",
                "44 85 63 08 0F 85 ? ? ? ? 48 8B 07 48 8B CF FF 90 ? ? ? ? 41 3B 86 ? ? ? ?",
                0,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "Mesh",
                "48 8B 99 ? ? ? ? 48 85 DB 74 09 F6 83 ? ? ? ? ? 75 08",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "ComponentLocation",
                "0F 10 88 ? ? ? ? 48 8D 44 24 ? 0F 28 C1 F3 0F 11 4C 24 ? 0F C6 C1 55 0F C6 C9 AA F3 0F 11 4C 24 ? F3 0F 11 44 24 ?",
                3,
            ),
            select: SelectMode::First,
        },
        // Extra sigs from sigs.txt (best-effort mapping)
        SigEntry {
            spec: Signature::offset(
                "AcknowledgedPawn",
                "48 8B 83 B8 04 00 00 48 89 84 24 90 00 00 00 4D 85 C0 75 10 48 8B D0 8B CE 48 8B 05 ? ? ? ? FF D0 EB 42",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "GroggyHealth",
                "41 0F 2F 89 ? ? ? ? 0F 82 ? ? ? ? E9 ? ? ? ?",
                4,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "SpectatedCount",
                "48 8B 03 48 8B CB FF 83 ? ? ? ? F3 0F 11 B3 ? ? ? ? FF 90 ? ? ? ? 48 85 C0 74 0D 83 B8 ? ? ? ? ? 0F 8F ? ? ? ?",
                0,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "ComponentToWorld",
                "0F 10 80 ? ? ? ? 0F 11 43 20 0F 10 88 ? ? ? ? 0F 11 4B 30 0F 10 80 ? ? ? ? 0F 11 43 40 48 8B 8B ? ? ? ?",
                3,
            ),
            select: SelectMode::First,
        },
        SigEntry {
            spec: Signature::offset(
                "ComponentVelocity",
                "48 8B 91 ? ? ? ? 48 85 D2 74 1C F2 0F 10 81 ? ? ? ? F2 0F 11 82 ? ? ? ? 8B 81 ? ? ? ? 89 82 ? ? ? ?",
                3,
            ),
            select: SelectMode::First,
        },
    ];

    log::info!("Scanning signatures (resilient)...");
    let mut out = String::new();
    for entry in &signatures {
        let result = match entry.select {
            SelectMode::First => match entry.spec.value_type {
                SignatureType::Offset => handle
                    .resolve_signature_struct_offset_resilient(
                        Module::Game,
                        &entry.spec,
                        false,
                        false,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "resolve_signature_struct_offset_resilient(first) for {} failed: {}",
                            entry.spec.debug_name,
                            e
                        )
                    }),
                SignatureType::RelativeAddress { .. } => handle
                    .resolve_signature_resilient(Module::Game, &entry.spec)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "resolve_signature_resilient for {} failed: {}",
                            entry.spec.debug_name,
                            e
                        )
                    }),
            },
            SelectMode::Last => match entry.spec.value_type {
                SignatureType::Offset => handle
                    .resolve_signature_struct_offset_resilient(
                        Module::Game,
                        &entry.spec,
                        false,
                        true,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "resolve_signature_struct_offset_resilient(last) for {} failed: {}",
                            entry.spec.debug_name,
                            e
                        )
                    }),
                SignatureType::RelativeAddress { .. } => handle
                    .resolve_signature_resilient_last(Module::Game, &entry.spec)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "resolve_signature_resilient_last for {} failed: {}",
                            entry.spec.debug_name,
                            e
                        )
                    }),
            },
        };
        match result {
            Ok(Some(value)) => match entry.spec.value_type {
                SignatureType::RelativeAddress { .. } => {
                    log::info!(
                        "{}: abs {:#x} (RVA {:#x})",
                        entry.spec.debug_name,
                        value,
                        value - module_address
                    );
                    let _ = writeln!(out, "{} = 0x{:X} (abs)", entry.spec.debug_name, value);
                }
                SignatureType::Offset => {
                    log::info!("{}: offset {:#x}", entry.spec.debug_name, value);
                    let _ = writeln!(out, "{} = 0x{:X}", entry.spec.debug_name, value);
                }
            },
            Ok(None) => {
                log::warn!("{}: not found", entry.spec.debug_name);
                let _ = writeln!(out, "{} = NOT_FOUND", entry.spec.debug_name);
            }
            Err(err) => {
                let msg = format!("{}", err);
                if msg.to_lowercase().contains("paged out") {
                    log::error!(
                        "{}: failed due to paged out memory: {}",
                        entry.spec.debug_name,
                        msg
                    );
                } else {
                    log::error!("{}: failed: {}", entry.spec.debug_name, msg);
                }
                let _ = writeln!(out, "{} = ERROR: {}", entry.spec.debug_name, msg);
            }
        }
    }

    std::fs::write("offsets.txt", out)?;

    log::info!("Done");
    Ok(())
}
