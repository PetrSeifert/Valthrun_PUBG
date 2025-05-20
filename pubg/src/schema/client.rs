use raw_struct::{
    builtins::Ptr64,
    raw_struct,
};

use crate::EncryptedPtr64;

pub const ENTRY_OFFSET: u64 = 0xFFD9DE8;

#[raw_struct(size = 0x8)]
pub struct Entry {
    #[field(offset = 0x0)]
    pub u_world: EncryptedPtr64<dyn UWorld>,
}

#[raw_struct(size = 0x860)]
pub struct UWorld {
    #[field(offset = 0x858)]
    pub u_level: EncryptedPtr64<dyn ULevel>,

    #[field(offset = 0x178)]
    pub game_instance: EncryptedPtr64<dyn GameInstance>,
}

#[raw_struct(size = 0x278)]
pub struct ULevel {
    #[field(offset = 0x90)]
    pub actors: EncryptedPtr64<dyn TArray<Ptr64<dyn AActor>>>,

    #[field(offset =  0x270)]
    pub actors_for_gc: EncryptedPtr64<dyn TArray<Ptr64<dyn AActor>>>,
}

#[raw_struct(size = 0x38)]
pub struct GameInstance {
    /*#[field(offset = 0x60)]
    pub local_players: Ptr64<dyn EncryptedTArray<dyn ULocalPlayer>>,*/
    #[field(offset = 0x30)]
    pub local_player: Ptr64<EncryptedPtr64<dyn ULocalPlayer>>,
}

#[raw_struct(size = 0x38)]
pub struct ULocalPlayer {
    #[field(offset = 0x30)]
    pub player_controller: EncryptedPtr64<dyn APlayerController>,
}
impl AActor for dyn ULocalPlayer {}

#[raw_struct(size = 0x10)]
pub struct TArray<T>
where
    T: Send + Sync + 'static,
{
    #[field(offset = 0x0)]
    pub data: Ptr64<[T]>,

    #[field(offset = 0x8)]
    pub count: u32,

    #[field(offset = 0x10)]
    pub max: u32,
}

#[raw_struct(size = 0x10)]
pub struct EncryptedTArray<T>
where
    T: Send + Sync + 'static,
{
    #[field(offset = 0x0)]
    pub data: EncryptedPtr64<[T]>,

    #[field(offset = 0x8)]
    pub count: u32,

    #[field(offset = 0xC)]
    pub max: u32,
}

#[raw_struct(size = 0x318)]
pub struct AActor {
    #[field(offset = 0x20)]
    pub id: u32,

    #[field(offset = 0x310)]
    pub root_component: EncryptedPtr64<dyn USceneComponent>,
}

#[raw_struct(size = 0x4D8)]
pub struct APlayerController {
    #[field(offset = 0x430)]
    pub player_state: Ptr64<()>,

    #[field(offset = 0x4A8)]
    pub acknowledged_pawn: Ptr64<dyn APawn>,

    #[field(offset = 0x4D0)]
    pub player_camera_manager: Ptr64<dyn APlayerCameraManager>,
}
impl AActor for dyn APlayerController {}

#[raw_struct(size = 0x26C4)]
pub struct APawn {
    #[field(offset = 0x1870)]
    pub last_team_num: u32,

    #[field(offset = 0x26C0)]
    pub spectated_count: u32,
}
impl AActor for dyn APawn {}

#[raw_struct(size = 0xA46)]
pub struct ACharacter {
    #[field(offset = 0x48)]
    pub health_flag: u8,

    #[field(offset = 0x578)]
    pub mesh: Ptr64<u64>,

    #[field(offset = 0xA30)]
    pub health: f32,

    #[field(offset = 0x960)]
    pub health1: u32,

    #[field(offset = 0x988)]
    pub health2: f32,

    #[field(offset = 0xA44)]
    pub health3: u8,

    #[field(offset = 0xA45)]
    pub health5: u8,

    #[field(offset = 0xA40)]
    pub health6: u32,
}
impl APawn for dyn ACharacter {}

#[raw_struct(size = 0x1BFC)]
pub struct APlayerCameraManager {
    #[field(offset = 0x1670)]
    pub camera_rot: [f32; 3],

    #[field(offset = 0x1BF0)]
    pub camera_pos: [f32; 3],
}
impl AActor for dyn APlayerCameraManager {}

#[raw_struct(size = 0x33C)]
pub struct USceneComponent {
    #[field(offset = 0x330)]
    pub relative_location: [f32; 3],
}
