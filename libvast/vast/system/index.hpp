/******************************************************************************
 *                    _   _____   __________                                  *
 *                   | | / / _ | / __/_  __/     Visibility                   *
 *                   | |/ / __ |_\ \  / /          Across                     *
 *                   |___/_/ |_/___/ /_/       Space and Time                 *
 *                                                                            *
 * This file is part of VAST. It is subject to the license terms in the       *
 * LICENSE file found in the top-level directory of this distribution and at  *
 * http://vast.io/license. No part of VAST, including this file, may be       *
 * copied, modified, propagated, or distributed except according to the terms *
 * contained in the LICENSE file.                                             *
 ******************************************************************************/

#pragma once

#include "vast/detail/flat_lru_cache.hpp"
#include "vast/detail/lru_cache.hpp"
#include "vast/detail/stable_map.hpp"
#include "vast/expression.hpp"
#include "vast/filesystem.hpp"
#include "vast/fwd.hpp"
#include "vast/meta_index.hpp"
#include "vast/system/accountant.hpp"
#include "vast/system/indexer_stage_driver.hpp"
#include "vast/system/partition.hpp"
#include "vast/system/query_supervisor.hpp"
#include "vast/system/spawn_indexer.hpp"
#include "vast/uuid.hpp"

#include <caf/actor.hpp>
#include <caf/behavior.hpp>
#include <caf/fwd.hpp>

#include <unordered_map>
#include <vector>

#include "caf/response_promise.hpp"

namespace vast::system {

namespace v2 {

/// The state of the active partition.
struct active_partition_state {
  caf::actor actor; ///< The partition actor.

  /// The slot ID that identifies the partition in the stream.
  caf::stream_slot stream_slot;

  /// The remaining free capacity of the partition.
  uint64_t capacity;

  /// The UUID of the partition.
  uuid id;
};

/// The state of the index actor.
struct index_state {
  using index_stream_stage_ptr
    = caf::stream_stage_ptr<table_slice_ptr,
                            caf::broadcast_downstream_manager<table_slice_ptr>>;

  // equivalent of lookup_state in the old index
  struct query_state {
    /// The UUID of the query.
    vast::uuid id;

    /// The query expression.
    vast::expression expression;

    /// The evaluators for this query
    // std::set<caf::actor> evaluators;

    /// Unscheduled partitions.
    std::vector<uuid> partitions;
  };

  /// Loads partitions from disk by UUID.
  class partition_factory {
  public:
    explicit partition_factory(index_state* st = nullptr) : st_(st) {
      // nop
    }

    caf::actor operator()(const uuid& id) const;

  private:
    index_state* st_;
  };

  /// Stores partitions sorted by access frequency.
  using partition_cache_type
    = detail::lru_cache<uuid, caf::actor, partition_factory>;

  using pending_query_map = detail::stable_map<uuid, evaluation_triples>;

  explicit index_state(caf::stateful_actor<index_state>* self);

  // -- persistence ------------------------------------------------------------

  /// Loads the state from disk.
  caf::error load_from_disk();

  /// Persists the state to disk.
  caf::error flush_to_disk();

  // -- query handling

  bool worker_available();

  caf::actor next_worker();

  /// Prepares a subset of partitions from the lookup_state for evaluation.
  // pending_query_map
  caf::response_promise
  build_query_map(query_state& lookup, uint32_t num_partitions);

  /// Spawns one evaluator for each partition.
  /// @returns a query map for passing to INDEX workers over the spawned
  ///          EVALUATOR actors.
  query_map launch_evaluators(pending_query_map pqm, expression expr);

  // -- data members ----------------------------------------------------------

  /// Pointer to the parent actor.
  caf::stateful_actor<index_state>* self;

  /// The streaming stage.
  index_stream_stage_ptr stage;

  /// Allows the index to multiplex between waiting for ready workers and
  /// queries.
  caf::behavior has_worker;

  /// The single active (read/write) partition.
  active_partition_state active_partition = {};

  /// Partitions that are currently in the process of persisting.
  /// TODO: An alternative to keeping an explicit set of unpersisted partitions
  /// would be to add functionality to the LRU cache to "pin" certain items.
  /// Then (assuming the query interface for both types of partition stays
  /// identical) we could just use the same cache for unpersisted partitions and
  /// unpin them after they're safely on disk.
  std::unordered_map<uuid, caf::actor> unpersisted;

  /// The set of passive (read-only) partitions.
  partition_cache_type lru_partitions;

  /// The set of partitions that exist on disk.
  /// TODO: not sure if we even need this
  std::vector<uuid> persisted_partitions;

  /// The maximum number of events that a partition can hold.
  size_t partition_capacity;

  size_t in_mem_partitions;

  size_t taste_partitions;

  /// Maps query IDs to pending lookup state.
  std::unordered_map<uuid, query_state> pending;

  /// Caches idle workers.
  std::vector<caf::actor> idle_workers;

  /// The meta index.
  meta_index meta_idx;

  /// The directory for persistent state.
  path dir;

  static inline const char* name = "index";
};

/// Indexes events in horizontal partitions.
/// @param dir The directory of the index.
/// @param partition_capacity The maximum number of events per partition.
/// @pre `partition_capacity > 0
caf::behavior index(caf::stateful_actor<index_state>* self, path dir,
                    size_t partition_capacity, size_t in_mem_partitions,
                    size_t taste_partitions, size_t num_workers);

} // namespace v2

/// State of an INDEX actor.
struct index_state {
  // -- member types -----------------------------------------------------------

  /// Function for spawning more INDEXER actors.
  using indexer_factory = decltype(spawn_indexer)*;

  /// Pointer to the stage that multiplexing traffic between our sources and
  /// the INDEXER actors of the current partition.
  using stage_ptr = indexer_stage_driver::stage_ptr_type;

  /// Looks up partitions in the LRU cache by UUID.
  class partition_lookup {
  public:
    auto operator()(const uuid& id) const {
      return [&](const partition_ptr& ptr) {
        return ptr->id() == id;
      };
    }
  };

  /// Loads partitions from disk by UUID.
  class partition_factory {
  public:
    explicit partition_factory(index_state* st) : st_(st) {
      // nop
    }

    partition_ptr operator()(const uuid& id) const;

  private:
    index_state* st_;
  };

  /// Stores partitions sorted by access frequency.
  using partition_cache_type = detail::flat_lru_cache<partition_ptr,
                                                      partition_lookup,
                                                      partition_factory>;

  /// Stores context information for unfinished queries.
  struct lookup_state {
    /// Issued query.
    expression expr;

    /// Unscheduled partitions.
    std::vector<uuid> partitions;
  };

  /// Stores evaluation metadata for pending partitions.
  using pending_query_map = detail::stable_map<uuid, evaluation_triples>;

  /// Accumulates statistics for a given layout.
  struct layout_statistics {
    uint64_t count; ///< Number of events indexed.
  };

  /// Accumulates statistics about indexed data.
  struct statistics {
    /// The number of events for a given layout.
    std::unordered_map<std::string, layout_statistics> layouts;
  };

  // -- constructors, destructors, and assignment operators --------------------

  explicit index_state(caf::stateful_actor<index_state>* self);

  ~index_state();

  /// Initializes the state.
  caf::error init(const path& dir, size_t max_events, uint32_t max_parts,
                  uint32_t taste_parts);

  // -- persistence ------------------------------------------------------------

  /// Loads the state from disk.
  caf::error load_from_disk();

  /// Persists the state to disk.
  caf::error flush_meta_index();

  /// Persists the state to disk.
  caf::error flush_statistics();

  /// Persists the state to disk.
  caf::error flush_to_disk();

  // -- convenience functions --------------------------------------------------

  /// Returns the file name for saving or loading statistics.
  path statistics_filename() const;

  /// Returns the file name for saving or loading the meta index.
  path meta_index_filename() const;

  /// @returns whether there's an idle worker available.
  bool worker_available();

  /// Takes the next worker from the idle workers stack and returns it.
  /// @pre `has_worker()`
  caf::actor next_worker();

  /// @returns various status metrics.
  caf::dictionary<caf::config_value> status() const;

  /// Creates a new partition owned by the INDEX (stored as `active`).
  void reset_active_partition();

  partition* get_or_add_partition(const table_slice_ptr& slice);

  /// @returns a new partition with random ID.
  partition_ptr make_partition();

  /// @returns a new partition with given ID.
  partition_ptr make_partition(uuid id);

  /// @returns a new INDEXER actor.
  caf::actor make_indexer(path filename, type column_type, uuid partition_id,
                          std::string fqn);

  /// Decrements the indexer count for a partition.
  void decrement_indexer_count(uuid pid);

  /// @returns the unpersisted partition matching `id` or `nullptr` if no
  ///          partition matches.
  partition* find_unpersisted(const uuid& id);

  /// Prepares a subset of partitions from the lookup_state for evaluation.
  pending_query_map
  build_query_map(lookup_state& lookup, uint32_t num_partitions);

  /// Spawns one evaluator for each partition.
  /// @returns a query map for passing to INDEX workers over the spawned
  ///          EVALUATOR actors.
  query_map launch_evaluators(pending_query_map pqm, expression expr);

  /// Adds a new flush listener.
  void add_flush_listener(caf::actor listener);

  /// Sends a notification to all listeners and clears the listeners list.
  void notify_flush_listeners();

  // -- member variables -------------------------------------------------------

  /// Pointer to the parent actor.
  caf::stateful_actor<index_state>* self;

  /// Allows to select partitions with timestamps.
  meta_index meta_idx;

  /// Base directory for all partitions of the index.
  path dir;

  /// Stream manager for ingesting events.
  stage_ptr stage;

  /// The maximum number of events per partition.
  size_t max_partition_size;

  /// The number of partitions to schedule immediately for each query.
  uint32_t taste_partitions;

  /// Allows the index to multiplex between waiting for ready workers and
  /// queries.
  caf::behavior has_worker;

  /// Maps query IDs to pending lookup state.
  std::unordered_map<uuid, lookup_state> pending;

  /// Caches idle workers.
  std::vector<caf::actor> idle_workers;

  /// Spawns an INDEXER actor. Default-initialized to `spawn_indexer`, but
  /// allows users to redirect to other implementations (primarily for unit
  /// testing).
  indexer_factory factory;

  /// Our current partition.
  partition_ptr active;

  /// Active indexer count for the current partition.
  size_t active_partition_indexers = 0;

  /// Recently accessed partitions.
  partition_cache_type lru_partitions;

  /// Stores partitions that are no longer active but have not persisted their
  /// state yet.
  std::vector<std::pair<partition_ptr, size_t>> unpersisted;

  accountant_type accountant;

  /// List of actors that wait for the next flush event.
  std::vector<caf::actor> flush_listeners;

  /// Statistics about processed data.
  statistics stats;

  /// Name of the INDEX actor.
  static inline const char* name = "index";
};

/// @relates index_state
template <class Inspector>
auto inspect(Inspector& f, index_state::layout_statistics& x) {
  return f(x.count);
}

/// @relates index_state
template <class Inspector>
auto inspect(Inspector& f, index_state::statistics& x) {
  return f(x.layouts);
}

/// Indexes events in horizontal partitions.
/// @param dir The directory of the index.
/// @param max_partition_size The maximum number of events per partition.
/// @param in_mem_partitions The maximum number of partitions to hold in memory.
/// @param taste_partitions The number of partitions to schedule immediately
///                         for each query
/// @pre `max_partition_size > 0 && in_mem_partitions > 0`
caf::behavior index(caf::stateful_actor<index_state>* self, const path& dir,
                    size_t max_partition_size, size_t in_mem_partitions,
                    size_t taste_partitions, size_t num_workers);

} // namespace vast::system
