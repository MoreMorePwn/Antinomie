#include "host_api.h"
/* Matched compile-time assertions also live in transport.rs. */
_Static_assert(sizeof(struct ant_backing) == 16, "backing layout");
_Static_assert(sizeof(struct ant_memory_region) == 32, "region layout");
_Static_assert(offsetof(struct ant_memory_region, backing_index) == 24, "region index");
_Static_assert(sizeof(struct ant_options) == 72, "options layout");
_Static_assert(offsetof(struct ant_options, ram_size) == 32, "RAM option");
_Static_assert(offsetof(struct ant_options, bootstrap_gpa) == 40, "bootstrap option");
_Static_assert(offsetof(struct ant_options, init_timeout_ms) == 48, "timeout option");
_Static_assert(offsetof(struct ant_options, poll_mode) == 60, "poll mode option");
_Static_assert(sizeof(struct ant_stats) == 80, "stats layout");
_Static_assert(offsetof(struct ant_stats, waits) == 48, "stats waits");
_Static_assert(offsetof(struct ant_stats, health) == 32, "stats health");
_Static_assert(sizeof(struct ant_limits) == 24, "limits layout");
