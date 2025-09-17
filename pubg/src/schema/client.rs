use raw_struct::{
    builtins::Ptr64,
    raw_struct,
};

use crate::EncryptedPtr64;

pub const ENTRY_OFFSET: u64 = 0x10910A98; // GWorld

#[raw_struct(size = 0x8)]
pub struct Entry {
    #[field(offset = 0x0)]
    pub u_world: EncryptedPtr64<dyn UWorld>,
}

#[raw_struct(size = 0x0870)]
pub struct UWorld {
    #[field(offset = 0x0110)]
    pub u_level: EncryptedPtr64<dyn ULevel>,

    #[field(offset = 0x868)]
    pub game_instance: EncryptedPtr64<dyn GameInstance>,
}

#[raw_struct(size = 0x01E8)]
pub struct ULevel {
    #[field(offset = 0x01E0)]
    pub actors: EncryptedPtr64<dyn TArray<Ptr64<dyn AActor>>>,
}

#[raw_struct(size = 0x00F8)]
pub struct GameInstance {
    #[field(offset = 0x00F0)]
    pub local_player: Ptr64<EncryptedPtr64<dyn ULocalPlayer>>,
}

#[raw_struct(size = 0x0038)]
pub struct ULocalPlayer {
    #[field(offset = 0x0030)]
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

#[raw_struct(size = 0x0030)]
pub struct AActor {
    #[field(offset = 0x0010)]
    pub id: u32,

    #[field(offset = 0x0028)]
    pub root_component: EncryptedPtr64<dyn USceneComponent>,
}

#[raw_struct(size = 0x04C8)]
pub struct APlayerController {
    #[field(offset = 0x04C0)]
    pub player_camera_manager: Ptr64<dyn APlayerCameraManager>,
}
impl AActor for dyn APlayerController {}

#[raw_struct(size = 0x1CA4)]
pub struct APawn {
    #[field(offset = 0x1CA0)]
    pub last_team_num: u32,
}
impl AActor for dyn APawn {}

#[raw_struct(size = 0x0A44)]
pub struct ACharacter {
    #[field(offset = 0x0480)]
    pub mesh: Ptr64<dyn USkeletalMeshComponent>,

    #[field(offset = 0x0350)]
    pub health_flag: u8,

    #[field(offset = 0x0980)]
    pub health: f32,

    #[field(offset = 0x0970)]
    pub health1: u32,

    #[field(offset = 0x0A40)]
    pub health2: f32,

    #[field(offset = 0x0994)]
    pub health3: u8,

    #[field(offset = 0x0995)]
    pub health5: u8,

    #[field(offset = 0x0990)]
    pub health6: u32,
}
impl APawn for dyn ACharacter {}

#[raw_struct(size = 0x0489)]
pub struct USkeletalMeshComponent {
    #[field(offset = 0x0488)]
    pub always_create_physics_state: u8,
}

#[raw_struct(size = 0x15AC)]
pub struct APlayerCameraManager {
    #[field(offset = 0x15A0)]
    pub camera_rot: [f32; 3],

    #[field(offset = 0x1014)]
    pub camera_pos: [f32; 3],
}
impl AActor for dyn APlayerCameraManager {}

#[raw_struct(size = 0x02FC)]
pub struct USceneComponent {
    #[field(offset = 0x02F0)]
    pub relative_location: [f32; 3],
}
