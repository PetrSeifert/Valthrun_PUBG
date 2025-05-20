use anyhow::Context;
use pubg::{
    schema::{
        AActor,
        ACharacter,
        APawn,
    },
    state::{
        StateActorLists,
        StateDecrypt,
        StateGNameCache,
        StateLocalPlayerInfo,
        StatePlayerInfo,
        StatePlayerInfoParams,
    },
    StatePubgHandle,
    StatePubgMemory,
};
use raw_struct::builtins::Ptr64;
use utils_state::StateRegistry;

use super::Enhancement;

pub struct PlayerSpyer {}

impl PlayerSpyer {
    pub fn collect_players_info(
        &self,
        states: &StateRegistry,
        actor_list: &Vec<(u64, Ptr64<dyn AActor>)>,
        players_data: &mut Vec<(StatePlayerInfo, u32, u32, i32)>,
    ) -> anyhow::Result<()> {
        let decrypt = states.resolve::<StateDecrypt>(())?;
        let pubg_handle = states.resolve::<StatePubgHandle>(())?;
        let mut gname_cache = states.resolve_mut::<StateGNameCache>(())?;
        let memory = states.resolve::<StatePubgMemory>(())?;
        let local_player_info = states.resolve::<StateLocalPlayerInfo>(())?;

        for (_actor_address, actor_ptr) in actor_list.iter() {
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

            let root_component = match actor
                .root_component()?
                .value_reference(memory.view_arc(), &decrypt)
            {
                Some(root_component) => root_component,
                None => {
                    continue;
                }
            };

            let character = actor.cast::<dyn ACharacter>();
            let team_id = character.last_team_num()?;

            let player_info = states.resolve::<StatePlayerInfo>(StatePlayerInfoParams {
                character,
                root_component,
            })?;

            if player_info.health < 1 || player_info.health > 100 {
                continue;
            }

            let distance = ((player_info.position[0] - local_player_info.location[0]).powi(2)
                + (player_info.position[1] - local_player_info.location[1]).powi(2)
                + (player_info.position[2] - local_player_info.location[2]).powi(2))
            .sqrt() as u32;

            let difference = [
                player_info.position[0] - local_player_info.location[0],
                player_info.position[1] - local_player_info.location[1],
                player_info.position[2] - local_player_info.location[2],
            ];

            // Calculate horizontal angle to target (atan2 gives us angle in radians)
            let target_angle = difference[1].atan2(difference[0]);

            // Get player's horizontal angle (z rotation)
            let player_angle = local_player_info.rotation[1].to_radians();

            // Calculate the difference and convert to degrees
            let angle_diff = (target_angle - player_angle).to_degrees();

            // Normalize angle to -180 to 180 degrees
            let angle_diff = if angle_diff > 180.0 {
                (angle_diff - 360.0) as i32
            } else if angle_diff < -180.0 {
                (angle_diff + 360.0) as i32
            } else {
                angle_diff as i32
            };

            players_data.push((player_info.clone(), distance, team_id, angle_diff));
        }
        Ok(())
    }
}

impl Enhancement for PlayerSpyer {
    fn update(&mut self, ctx: &crate::UpdateContext) -> anyhow::Result<()> {
        let actor_lists = ctx.states.resolve::<StateActorLists>(())?;

        let mut players_data: Vec<(StatePlayerInfo, u32, u32, i32)> = Vec::new();
        let mut players_data_for_gc: Vec<(StatePlayerInfo, u32, u32, i32)> = Vec::new();

        let cached_actors = actor_lists.cached_actors();
        for (_actor_id, actor_list) in cached_actors {
            self.collect_players_info(&ctx.states, actor_list, &mut players_data)?;
        }

        let cached_actors_for_gc = actor_lists.cached_actors_for_gc();
        for (_actor_id, actor_list) in cached_actors_for_gc {
            self.collect_players_info(&ctx.states, actor_list, &mut players_data_for_gc)?;
        }

        if !players_data.is_empty() {
            players_data.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            let first_team = players_data[0].2;
            players_data.retain(|x| x.2 != first_team);

            players_data.dedup_by(|a, b| a.1 == b.1);

            for (player_info, distance, team_id, angle) in players_data {
                log::info!(
                    "Distance: {} Health: {} Angle: {} Team: {}",
                    distance,
                    player_info.health,
                    angle,
                    team_id
                );
            }
            return Ok(());
        }

        if !players_data_for_gc.is_empty() {
            players_data_for_gc.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            let first_team = players_data_for_gc[0].2;
            players_data_for_gc.retain(|x| x.2 != first_team);

            players_data_for_gc.dedup_by(|a, b| a.1 == b.1);

            for (player_info, distance, team_id, angle) in players_data_for_gc {
                log::info!(
                    "GC: Distance: {} Health: {} Angle: {} Team: {}",
                    distance,
                    player_info.health,
                    angle,
                    team_id
                );
            }
            return Ok(());
        }

        Ok(())
    }
}
