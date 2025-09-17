use std::{
    cell::Ref,
    hash::Hash,
};

use raw_struct::{
    FromMemoryView,
    Reference,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};

use crate::{
    schema::{
        ACharacter,
        USceneComponent,
    },
    StatePubgMemory,
};

pub struct StatePlayerInfoParams {
    pub character: Reference<dyn ACharacter>,
    pub root_component: Reference<dyn USceneComponent>,
}

impl PartialEq for StatePlayerInfoParams {
    fn eq(&self, other: &Self) -> bool {
        self.character.reference_address() == other.character.reference_address()
            && self.root_component.reference_address() == other.root_component.reference_address()
    }
}

impl Hash for StatePlayerInfoParams {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.character.reference_address().hash(state);
        self.root_component.reference_address().hash(state);
    }
}

#[derive(Debug, Clone)]
pub struct StatePlayerInfo {
    pub position: [f32; 3],
    pub health: u32,
    pub physics_state: u8,
}

impl StatePlayerInfo {
    pub fn new() -> Self {
        Self {
            position: [0.0; 3],
            health: 0,
            physics_state: 0,
        }
    }

    /// XOR keys used for player health decryption
    const HEALTH_XOR_KEYS: [u32; 16] = [
        0xCEC7A59A, 0x9B63B2F1, 0xCAF395BD, 0xF138486B, 0xEC911D0A, 0x23DDA8D3, 0x9456BC8,
        0xBD39B321, 0xBA87A58, 0xA8EFF187, 0xE275E4B3, 0x9F8ADBF0, 0xBDEC34D5, 0xF1936B07,
        0x6B099E38, 0xE7D22A2B,
    ];

    const HEALTH4: u32 = 0x0980; // Health4

    pub fn decrypt_player_health(value: &mut [u8], offset: u32) {
        let xor_keys = unsafe {
            std::slice::from_raw_parts((&Self::HEALTH_XOR_KEYS as *const u32) as *const u8, 64)
        };
        let size = value.len() as u32;
        for i in 0..size as usize {
            value[i] ^= xor_keys[(i as u32 + offset) as usize & 0x3F];
        }
    }

    pub fn get_health(
        actor: Reference<dyn ACharacter>,
        memory: Ref<'_, StatePubgMemory>,
    ) -> anyhow::Result<f32> {
        let b_health_flag = actor.health_flag()? != 3;
        let b_health1 = actor.health1()? != 0;

        if b_health_flag && b_health1 {
            let b_is_encrypted = actor.health5()? != 0;
            let health3 = actor.health3()?;

            let mut health4 = f32::read_object(
                memory.view(),
                health3 as u64 + actor.reference_address() + Self::HEALTH4 as u64,
            )
            .map_err(|err| anyhow::anyhow!("{}", err))?;

            if b_is_encrypted {
                let mut health4_bytes = health4.to_le_bytes();
                Self::decrypt_player_health(&mut health4_bytes, actor.health6()?);
                health4 = f32::from_le_bytes(health4_bytes);
            }

            Ok(health4)
        } else {
            Ok(actor.health2()?)
        }
    }
}

impl State for StatePlayerInfo {
    type Parameter = StatePlayerInfoParams;

    fn create(states: &StateRegistry, params: Self::Parameter) -> anyhow::Result<Self> {
        let memory = states.resolve::<StatePubgMemory>(())?;

        let mesh = params.character.mesh()?.value_reference(memory.view_arc());
        let physics_state = match mesh {
            Some(mesh) => mesh.always_create_physics_state()?,
            None => 0,
        };

        let health = Self::get_health(params.character, memory)?;
        let health = health as u32;

        let relative_location = params.root_component.relative_location()?;

        Ok(Self {
            position: relative_location,
            health,
            physics_state,
        })
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Volatile
    }
}
