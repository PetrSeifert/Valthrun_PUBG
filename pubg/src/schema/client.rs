use raw_struct::{
    builtins::Ptr64,
    raw_struct,
};

use crate::EncryptedPtr64;

pub const ENTRY_OFFSET: u64 = 0x10FFB298; // GWorld

#[raw_struct(size = 0x8)]
pub struct Entry {
    #[field(offset = 0x0)]
    pub u_world: EncryptedPtr64<dyn UWorld>,
}

#[raw_struct(size = 0x0AA8)]
pub struct UWorld {
    #[field(offset = 0x0AA0)]
    pub u_level: EncryptedPtr64<dyn ULevel>,

    #[field(offset = 0x110)]
    pub game_instance: EncryptedPtr64<dyn GameInstance>,
}

#[raw_struct(size = 0x00D8)]
pub struct ULevel {
    #[field(offset = 0x00D0)]
    pub actors: EncryptedPtr64<dyn TArray<Ptr64<dyn AActor>>>,
}

#[raw_struct(size = 0x0048)]
pub struct GameInstance {
    #[field(offset = 0x0040)]
    pub local_player: Ptr64<EncryptedPtr64<dyn ULocalPlayer>>,
}

#[raw_struct(size = 0x0040)]
pub struct ULocalPlayer {
    #[field(offset = 0x0038)]
    pub player_controller: EncryptedPtr64<dyn APlayerController>,
}
impl AActor for dyn ULocalPlayer {}

#[raw_struct(size = 0x14)]
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

#[raw_struct(size = 0x0358)]
pub struct AActor {
    #[field(offset = 0x0018)]
    pub id: u32,

    #[field(offset = 0x0350)]
    pub root_component: EncryptedPtr64<dyn USceneComponent>,
}

#[raw_struct(size = 0x04D0)]
pub struct APlayerController {
    #[field(offset = 0x04C8)]
    pub player_camera_manager: Ptr64<dyn APlayerCameraManager>,
}
impl AActor for dyn APlayerController {}

#[raw_struct(size = 0x12F4)]
pub struct APawn {
    #[field(offset = 0x12F0)]
    pub last_team_num: u32,
}
impl AActor for dyn APawn {}

#[raw_struct(size = 0x0A20)]
pub struct ACharacter {
    #[field(offset = 0x0780)]
    pub mesh: EncryptedPtr64<dyn USkeletalMeshComponent>,

    #[field(offset = 0x010C)]
    pub health_flag: u8,

    #[field(offset = 0x0A00)]
    pub health: f32,

    #[field(offset = 0x0A1C)]
    pub health1: u32,

    #[field(offset = 0x0A18)]
    pub health2: f32,

    #[field(offset = 0x0A14)]
    pub health3: u8,

    #[field(offset = 0x0A15)]
    pub health5: u8,

    #[field(offset = 0x0A10)]
    pub health6: u32,
}
impl APawn for dyn ACharacter {}

#[raw_struct(size = 0x0499)]
pub struct USkeletalMeshComponent {
    #[field(offset = 0x0498)]
    pub always_create_physics_state: u8,
}

#[raw_struct(size = 0x1034)]
pub struct APlayerCameraManager {
    #[field(offset = 0x0A90)]
    pub camera_rot: [f32; 3],

    #[field(offset = 0x1028)]
    pub camera_pos: [f32; 3],
}
impl AActor for dyn APlayerCameraManager {}

#[raw_struct(size = 0x026C)]
pub struct USceneComponent {
    #[field(offset = 0x0260)]
    pub relative_location: [f32; 3],
}
