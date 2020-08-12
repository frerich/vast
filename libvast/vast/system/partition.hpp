/******************************************************************************

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

#include "vast/detail/stable_map.hpp"
#include "vast/fbs/partition.hpp"
#include "vast/filesystem.hpp"
#include "vast/fwd.hpp"
#include "vast/ids.hpp"
#include "vast/qualified_record_field.hpp"
#include "vast/system/instrumentation.hpp"
#include "vast/system/filesystem.hpp"
#include "vast/table_slice_column.hpp"
#include "vast/type.hpp"
#include "vast/uuid.hpp"

#include <caf/event_based_actor.hpp>
#include <caf/stream_slot.hpp>

#include <unordered_map>

#include "caf/fwd.hpp"

namespace vast::system {

// TODO: remove this temporary namespace after we have wired all functionality
// with the new actorized partition.
namespace v2 {

struct partition_selector {
  bool operator()(const vast::qualified_record_field& filter,
                  const table_slice_column& x) const;
};

/// The state of the partition actor.
struct partition_state {
  using partition_stream_stage_ptr = caf::stream_stage_ptr<
    table_slice_ptr,
    caf::broadcast_downstream_manager<
      table_slice_column, vast::qualified_record_field, partition_selector>>;

  /// Member functions

  /// Gets the INDEXER at position in the layout.
  caf::actor indexer_at(size_t position);

  /// Retrieves an INDEXER for a predicate with a data extractor.
  /// @param dx The extractor.
  /// @param op The operator (only used to precompute ids for type queries.
  /// @param x The literal side of the predicate.
  caf::actor fetch_indexer(const data_extractor& dx, relational_operator op,
                           const data& x);

  /// Retrieves an INDEXER for a predicate with an attribute extractor.
  /// @param ex The extractor.
  /// @param op The operator (only used to precompute ids for type queries.
  /// @param x The literal side of the predicate.
  caf::actor fetch_indexer(const attribute_extractor& ex,
                           relational_operator op, const data& x);

  /// Data Members

  /// Pointer to the parent actor.
  caf::stateful_actor<partition_state>* self;

  /// Uniquely identifies this partition.
  uuid partition_uuid;

  /// The streaming stage.
  partition_stream_stage_ptr stage;

  /// The combined type of all columns of this partition
  record_type combined_layout;

  /// Maps qualified fields to indexer actors.
  //  TODO: Should we use the tsl map here for heterogenous key lookup?
  detail::stable_map<qualified_record_field, caf::actor> indexers;

  /// Maps type names to ids. Used the answer #type queries.
  // FIXME: This either needs to go into the flatbuffer, or be restored upon
  // loading.
  std::unordered_map<std::string, ids> type_ids;

  /// A readable name for this partition
  std::string name;

  /// The first ID in the partition.
  id offset;

  /// The number of events in the partition.
  size_t events;

  /// Persistence-related state
  filesystem_type fs_actor;
  caf::response_promise persistence_promise;
  std::optional<path> persist_path;
  size_t persisted_indexers;
  std::map<caf::actor_id, vast::chunk_ptr> chunks;
};

// TODO: Split this into a `static data` part that can be mmap'ed
// straight from disk, and an actor-related part. In the ideal case,
// we want to eventually be able to use the on-disk state without
// any intermediate deserialization step, like yandex::mms or cap'n proto.
struct readonly_partition_state {
  // FIXME: Move these functions, together with `combined_layout` and
  caf::actor indexer_at(size_t position);

  caf::actor fetch_indexer(const data_extractor& dx, relational_operator op,
                           const data& x);

  caf::actor fetch_indexer(const attribute_extractor& ex,
                           relational_operator op, const data& x);

  /// Pointer to the parent actor.
  caf::stateful_actor<partition_state>* self;

  /// Uniquely identifies this partition.
  uuid partition_uuid;

  /// The combined type of all columns of this partition
  record_type combined_layout;

  /// Maps type names to ids. Used the answer #type queries.
  std::unordered_map<std::string, ids> type_ids;

  /// A readable name for this partition
  std::string name;

  /// The first ID in the partition.
  size_t offset;

  /// The number of events in the partition.
  size_t events;

  // Stores the deserialized indexers.
  std::map<qualified_record_field, value_index_ptr> indexer_states;

  /// Maps qualified fields to indexer actors.
  detail::stable_map<qualified_record_field, caf::actor> indexers;
};

// Flatbuffer support

caf::expected<flatbuffers::Offset<fbs::Partition>>
pack(flatbuffers::FlatBufferBuilder& builder, const partition_state& x);

caf::error unpack(const fbs::Partition& x, readonly_partition_state& y);

// TODO: Use typed actors for the partition actors.

/// Spawns a partition.
/// @param self The partition actor.
/// @param id The UUID of this partition.
caf::behavior partition(caf::stateful_actor<partition_state>* self, uuid id);

/// Spawns a read-only partition.
/// TODO: Maybe we should just send the path here, then the actual loading of
/// the chunk can be done asynchronously
caf::behavior
readonly_partition(caf::stateful_actor<readonly_partition_state>* self, uuid id,
                   vast::chunk chunk);

} // namespace v2

struct index_state;
class indexer_downstream_manager;

/// The horizontal data scaling unit of the index. A partition represents a
/// slice of indexes for a specific ID interval.
class partition {
public:
  // -- member types -----------------------------------------------------------

  /// Persistent meta state for the partition.
  struct meta_data {
    /// Keeps a list of already added layouts so we don't have to check if
    /// additional columns have to be spawned for each added slice.
    std::unordered_set<record_type> layouts;

    /// Maps type names to ids. Used the answer #type queries.
    std::unordered_map<std::string, ids> type_ids;

    /// Stores whether the partition has been mutated in memory.
    bool dirty = false;
  };

  /// An indexer combined withs streaming support structures.
  struct wrapped_indexer {
    /// Mutable because it can be initalized layzily.
    mutable caf::actor indexer;

    /// The slot is used by the indexer_downstream_manager during ingestion.
    caf::stream_slot slot;

    /// The message queue of the downstream indexer.
    /// This is used by the indexer_downstream_manager, the pointed-to object is
    /// removed when the partition is removed from said manager.
    caf::outbound_path* outbound;

    /// A buffer to avoid overloading the indexer.
    /// Only used during ingestion.
    std::vector<table_slice_column> buf;
  };

  // -- constructors, destructors, and assignment operators --------------------

  /// @param self The parent actor.
  /// @param id Unique identifier for this partition.
  /// @param max_capacity The amount of events this partition can hold.
  /// @pre `self != nullptr`
  /// @pre `factory != nullptr`
  partition(index_state* state, uuid id, size_t max_capacity);

  ~partition() noexcept;

  // -- persistence ------------------------------------------------------------

  /// Materializes the partition layouts from disk.
  /// @returns an error if I/O operations fail.
  caf::error init();

  /// Persists the partition layouts to disk.
  /// @returns an error if I/O operations fail.
  caf::error flush_to_disk();

  // -- properties -------------------------------------------------------------

  /// @returns the unique ID of the partition.
  auto& id() const noexcept {
    return id_;
  }

  /// @returns the state of the owning INDEX actor.
  auto& state() noexcept {
    return *state_;
  }

  /// @returns the remaining capacity in this partition.
  auto capacity() const noexcept {
    return capacity_;
  }

  /// @returns a record type containing all columns of this partition.
  // TODO: Should this be renamed to layout()?
  record_type combined_type() const;

  /// @returns the directory for persistent state.
  path base_dir() const;

  /// @returns the file name for saving or loading the ::meta_data.
  path meta_file() const;

  indexer_downstream_manager& out() const;

  /// @returns the file name for `column`.
  path column_file(const qualified_record_field& field) const;

  // -- operations -------------------------------------------------------------

  /// Adds a slice to the partition.
  void add(table_slice_ptr slice);

  /// Gets the INDEXER at position in the layout.
  caf::actor& indexer_at(size_t position);

  /// Retrieves an INDEXER for a predicate with a data extractor.
  /// @param dx The extractor.
  /// @param op The operator (only used to precompute ids for type queries.
  /// @param x The literal side of the predicate.
  caf::actor fetch_indexer(const data_extractor& dx, relational_operator op,
                           const data& x);

  /// Retrieves an INDEXER for a predicate with an attribute extractor.
  /// @param dx The extractor.
  /// @param op The operator (only used to precompute ids for type queries.
  /// @param x The literal side of the predicate.
  caf::actor fetch_indexer(const attribute_extractor& ex,
                           relational_operator op, const data& x);

  /// @returns all INDEXER actors required for a query, together with tailored
  /// predicates their offsets in the expression. Used by the EVALUATOR.
  evaluation_triples eval(const expression& expr);

  // -- members ----------------------------------------------------------------

  /// State of the INDEX actor that owns this partition.
  index_state* state_;

  /// Keeps track of row types in this partition.
  meta_data meta_data_;

  /// Uniquely identifies this partition.
  uuid id_;

  /// A map to the indexers.
  detail::stable_map<qualified_record_field, wrapped_indexer> indexers_;

  /// Remaining capacity in this partition.
  size_t capacity_;

  std::vector<table_slice_ptr> inbound_;

  friend struct index_state;
  friend class indexer_downstream_manager;
};

// -- related types ------------------------------------------------------------

/// @relates partition
using partition_ptr = std::unique_ptr<partition>;

// -- free functions -----------------------------------------------------------

/// @relates partition::meta_data
template <class Inspector>
auto inspect(Inspector& f, partition::meta_data& x) {
  return f(x.layouts, x.type_ids);
}

} // namespace vast::system

namespace std {

template <>
struct hash<vast::system::partition_ptr> {
  size_t operator()(const vast::system::partition_ptr& ptr) const;
};

} // namespace std
