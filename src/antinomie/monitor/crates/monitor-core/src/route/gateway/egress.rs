// SPDX-License-Identifier: GPL-3.0-only
//! The gateway's side of the egress abuse filter (`filter.rs`): asking it
//! about a new connection and counting what it refused.
use super::{Active, Counters, Instant, Loop};
use crate::route::{
    filter::{Block, FilterState},
    upstream::Dest,
};

impl Loop {
    /// Whether the egress filter lets a new connection to `dest` through on
    /// `route`; a refusal is counted by reason. Routes the filter does not
    /// cover (Drop, InetSim, a disabled filter) admit everything.
    pub(super) fn egress_admits(
        &mut self,
        route: &Active,
        generation: u64,
        dest: &Dest,
        now: Instant,
    ) -> bool {
        let Some(filter) = route.filter() else {
            return true;
        };
        if self.filter_generation != generation {
            self.filter_state = FilterState::default();
            self.filter_generation = generation;
        }
        let key = match dest {
            Dest::Ip(ip, _) => ip.to_string(),
            Dest::Name(name, _) => name.clone(),
        };
        let open = self
            .conns
            .values()
            .filter(|(_, conn)| conn.generation == generation)
            .count();
        match self
            .filter_state
            .admit(filter, now, &key, dest.port(), open, route.expired(now))
        {
            Ok(()) => true,
            Err(block) => {
                self.note_block(route, block);
                false
            }
        }
    }

    /// Counts a connection the egress filter refused.
    fn note_block(&self, route: &Active, block: Block) {
        let counters = &self.shared.counters;
        match block {
            Block::Port(port) => {
                Counters::add(&counters.filter_port, 1);
                if let Ok(mut ports) = route.blocked_ports.lock() {
                    *ports.entry(port).or_insert(0) += 1;
                }
            }
            Block::Rate => Counters::add(&counters.filter_rate, 1),
            Block::Concurrent => Counters::add(&counters.filter_concurrent, 1),
            Block::Destinations => Counters::add(&counters.filter_destinations, 1),
            Block::TimeLimit => Counters::add(&counters.filter_time, 1),
        }
    }
}
