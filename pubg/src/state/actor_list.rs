use std::collections::{
    HashMap,
    HashSet,
};

use anyhow::Context;
use raw_struct::{
    builtins::Ptr64,
    Reference,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};

use crate::{
    schema::{
        AActor,
        TArray,
    },
    state::{
        StateDecrypt,
        StateGNameCache,
        StateWorld,
    },
    StatePubgHandle,
    StatePubgMemory,
};

#[derive(Default)]
pub struct ActorCache {
    pub actors: HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>>,
    pub actors_for_gc: HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>>,
    tracked_addresses: HashSet<u64>,
    tracked_addresses_for_gc: HashSet<u64>,
}

pub struct StateActorLists {
    actors_array: Reference<dyn TArray<Ptr64<dyn AActor>>>,
    actors_for_gc_array: Reference<dyn TArray<Ptr64<dyn AActor>>>,
    cache: ActorCache,
}

impl State for StateActorLists {
    type Parameter = ();

    fn create(states: &StateRegistry, _: Self::Parameter) -> anyhow::Result<Self> {
        let memory = states.resolve::<StatePubgMemory>(())?;
        let decrypt = states.resolve::<StateDecrypt>(())?;
        let u_world = states.resolve::<StateWorld>(())?;

        let u_level = u_world
            .u_level()
            .context("u_level nullptr")?
            .value_reference(memory.view_arc(), &decrypt)
            .context("nullptr")?;

        let actor_array = u_level
            .actors()
            .context("actor_array nullptr")?
            .value_reference(memory.view_arc(), &decrypt)
            .context("nullptr")?;

        let actors_for_gc_array = u_level
            .actors_for_gc()
            .context("actors_for_gc_array nullptr")?
            .value_reference(memory.view_arc(), &decrypt)
            .context("nullptr")?;

        Ok(Self {
            actors_array: actor_array,
            actors_for_gc_array,
            cache: ActorCache::default(),
        })
    }

    fn update(&mut self, states: &StateRegistry) -> anyhow::Result<()> {
        let decrypt = states.resolve::<StateDecrypt>(())?;
        let pubg_handle = states.resolve::<StatePubgHandle>(())?;
        let memory = states.resolve::<StatePubgMemory>(())?;
        let mut gname_cache = states.resolve_mut::<StateGNameCache>(())?;
        self.update_cache(&decrypt, &pubg_handle, &memory, &mut gname_cache)?;
        Ok(())
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Persistent
    }
}

impl StateActorLists {
    pub fn update_cache(
        &mut self,
        decrypt: &StateDecrypt,
        pubg_handle: &StatePubgHandle,
        memory: &StatePubgMemory,
        gname_cache: &mut StateGNameCache,
    ) -> anyhow::Result<()> {
        let mut current_actors: HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>> = HashMap::new();
        let mut current_addresses = HashSet::new();

        // Scan through all actors and collect the ones we want to cache
        for actor_ptr in self
            .actors_array
            .data()?
            .elements(memory.view(), 0..self.actors_array.count()? as usize)?
        {
            if actor_ptr.is_null() {
                continue;
            }

            let actor = actor_ptr
                .value_reference(memory.view_arc())
                .context("actor nullptr")?;

            let name = gname_cache.get_gname_by_id(&decrypt, &pubg_handle, &memory, actor.id()?)?;

            if name != "PlayerFemale_A_C" && name != "PlayerMale_A_C" {
                continue;
            }

            let actor_addr = actor.reference_address();

            // Skip if we've never seen this actor with our IDs before
            if !self.cache.tracked_addresses.contains(&actor_addr) {
                let actor_id = match actor.id() {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                current_actors
                    .entry(actor_id)
                    .or_default()
                    .push((actor_addr, actor_ptr.clone()));

                current_addresses.insert(actor_addr);
            } else {
                // We know this actor's ID since we've seen it before
                for (id, actors) in &self.cache.actors {
                    if actors.iter().any(|(addr, _)| *addr == actor_addr) {
                        current_actors
                            .entry(*id)
                            .or_default()
                            .push((actor_addr, actor_ptr.clone()));
                        current_addresses.insert(actor_addr);
                        break;
                    }
                }
            }
        }

        let mut current_actors_for_gc: HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>> = HashMap::new();
        let mut current_addresses_for_gc = HashSet::new();

        // Scan through all actors and collect the ones we want to cache
        for actor_ptr in self
            .actors_for_gc_array
            .data()?
            .elements(memory.view(), 0..self.actors_for_gc_array.count()? as usize)?
        {
            if actor_ptr.is_null() {
                continue;
            }

            let actor = actor_ptr
                .value_reference(memory.view_arc())
                .context("actor nullptr")?;

            let name = gname_cache.get_gname_by_id(&decrypt, &pubg_handle, &memory, actor.id()?)?;

            if name != "PlayerFemale_A_C" && name != "PlayerMale_A_C" {
                continue;
            }

            let actor_addr = actor.reference_address();

            // Skip if we've never seen this actor with our IDs before
            if !self.cache.tracked_addresses_for_gc.contains(&actor_addr) {
                let actor_id = match actor.id() {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                current_actors_for_gc
                    .entry(actor_id)
                    .or_default()
                    .push((actor_addr, actor_ptr.clone()));

                current_addresses_for_gc.insert(actor_addr);
            } else {
                // We know this actor's ID since we've seen it before
                for (id, actors) in &self.cache.actors_for_gc {
                    if actors.iter().any(|(addr, _)| *addr == actor_addr) {
                        current_actors_for_gc
                            .entry(*id)
                            .or_default()
                            .push((actor_addr, actor_ptr.clone()));
                        current_addresses_for_gc.insert(actor_addr);
                        break;
                    }
                }
            }
        }

        self.cache.actors = current_actors;
        self.cache.tracked_addresses = current_addresses;
        self.cache.actors_for_gc = current_actors_for_gc;
        self.cache.tracked_addresses_for_gc = current_addresses_for_gc;
        Ok(())
    }

    pub fn get_cached_actors(&self, actor_id: u32) -> Option<&Vec<(u64, Ptr64<dyn AActor>)>> {
        self.cache.actors.get(&actor_id)
    }

    pub fn get_cached_actors_for_gc(
        &self,
        actor_id: u32,
    ) -> Option<&Vec<(u64, Ptr64<dyn AActor>)>> {
        self.cache.actors_for_gc.get(&actor_id)
    }

    pub fn cached_actors(&self) -> &HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>> {
        &self.cache.actors
    }

    pub fn cached_actors_for_gc(&self) -> &HashMap<u32, Vec<(u64, Ptr64<dyn AActor>)>> {
        &self.cache.actors_for_gc
    }

    pub fn clear(&mut self) {
        self.cache.actors.clear();
        self.cache.tracked_addresses.clear();
        self.cache.actors_for_gc.clear();
        self.cache.tracked_addresses_for_gc.clear();
    }
}
