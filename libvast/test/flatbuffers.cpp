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

#include "vast/chunk.hpp"
#include "vast/expression.hpp"
#include "vast/fbs/meta_index.hpp"
#include "vast/fbs/index.hpp"
#include "vast/fbs/utils.hpp"
#include "vast/fbs/uuid.hpp"
#include "vast/meta_index.hpp"
#include "vast/msgpack_table_slice.hpp"
#include "vast/msgpack_table_slice_builder.hpp"
#include "vast/span.hpp"
#include "vast/system/index.hpp"
#include "vast/system/partition.hpp"
#include "vast/system/posix_filesystem.hpp"
#include "vast/table_slice_header.hpp"
#include "vast/type.hpp"
#include "vast/uuid.hpp"

#include "vast/detail/spawn_container_source.hpp"



#define SUITE flatbuffers
#include "vast/test/test.hpp"
#include "vast/test/fixtures/actor_system_and_events.hpp"

using vast::byte;
using vast::span;

TEST(uuid roundtrip) {
  vast::uuid uuid = vast::uuid::random();
  auto expected_fb = vast::fbs::wrap(uuid, vast::fbs::file_identifier);
  REQUIRE(expected_fb);
  auto fb = *expected_fb;
  vast::uuid uuid2 = vast::uuid::random();
  CHECK_NOT_EQUAL(uuid, uuid2);
  span<const byte> span{reinterpret_cast<const byte*>(fb->data()), fb->size()};
  vast::fbs::unwrap<vast::fbs::UUID>(span, uuid2);
  CHECK_EQUAL(uuid, uuid2);
}

TEST(meta index roundtrip) {
  // Prepare a mini meta index. The meta index only looks at the layout of the
  // table slices it gets, so we feed it with an empty table slice.
  auto meta_idx = vast::meta_index{};
  auto mock_partition = vast::uuid::random();
  vast::table_slice_header header;
  header.layout = vast::record_type{{"x", vast::count_type{}}}.name("y");
  auto slice = vast::msgpack_table_slice::make(header);
  REQUIRE(slice);
  meta_idx.add(mock_partition, *slice);
  // Serialize meta index.
  auto expected_fb = vast::fbs::wrap(meta_idx, vast::fbs::file_identifier);
  REQUIRE(expected_fb);
  auto fb = *expected_fb;
  span<const byte> span{reinterpret_cast<const byte*>(fb->data()), fb->size()};
  // Deserialize meta index.
  vast::meta_index recovered_meta_idx;
  vast::fbs::unwrap<vast::fbs::MetaIndex>(span, recovered_meta_idx);
  // Check that lookups still work as expected.
  auto candidates = recovered_meta_idx.lookup(vast::expression{
    vast::predicate{vast::field_extractor{".x"}, vast::equal, vast::data{0u}},
  });
  REQUIRE_EQUAL(candidates.size(), 1u);
  CHECK_EQUAL(candidates[0], mock_partition);
}

TEST(index roundtrip) {
  vast::system::v2::index_state state(/*self = */ nullptr);
  // The active partition is not supposed to appear in the
  // created flatbuffer
  state.active_partition.id = vast::uuid::random();
  // Both unpersisted and persisted partitions should show up in the created flatbuffer.
  state.unpersisted[vast::uuid::random()] = nullptr;
  state.unpersisted[vast::uuid::random()] = nullptr;
  state.persisted_partitions.push_back(vast::uuid::random());
  state.persisted_partitions.push_back(vast::uuid::random());
  std::set<vast::uuid> expected_uuids;
  for (auto& kv : state.unpersisted)
    expected_uuids.insert(kv.first);
  for (auto& uuid : state.persisted_partitions)
    expected_uuids.insert(uuid);
  // Serialize the index.
  auto expected_fb = vast::fbs::wrap(state, vast::fbs::file_identifier);
  REQUIRE(expected_fb);
  auto fb = *expected_fb;
  auto span = as_bytes(fb);
  // Deserialize the index.
  auto idx = vast::fbs::GetIndex(span.data());
  // Check Index state.
  CHECK_EQUAL(idx->version(), vast::fbs::Version::v0);
  // We only check the presence and not the contents of the meta index
  // since that should be covered by the previous unit test.
  auto meta_idx = idx->meta_index();
  CHECK(meta_idx);
  auto partition_uuids = idx->partitions();
  REQUIRE(partition_uuids);
  CHECK_EQUAL(partition_uuids->size(), expected_uuids.size());
  std::set<vast::uuid> restored_uuids;
  for (auto uuid : *partition_uuids) {
    REQUIRE(uuid);
    vast::uuid restored_uuid;
    vast::unpack(*uuid, restored_uuid);
    restored_uuids.insert(restored_uuid);
  }
  CHECK_EQUAL(expected_uuids, restored_uuids);
}

TEST(empty partition roundtrip) {
  // Create partition state.
  vast::system::v2::partition_state state;
  state.name = "test_name";
  state.partition_uuid = vast::uuid::random();
  state.offset = 17;
  state.events = 23;
  state.combined_layout = vast::record_type{{"x", vast::count_type{}}}.name("y");
  // Serialize partition.
  auto expected_fb = vast::fbs::wrap(state);
  REQUIRE(expected_fb);
  auto span = as_bytes(*expected_fb);
  // Deserialize partition.
  vast::system::v2::readonly_partition_state readonly_state;
  auto partition = vast::fbs::GetPartition(span.data());
  REQUIRE(partition);
  unpack(*partition, readonly_state);
  CHECK_EQUAL(readonly_state.partition_uuid, state.partition_uuid);
  CHECK_EQUAL(readonly_state.offset, state.offset);
  CHECK_EQUAL(readonly_state.events, state.events);
  CHECK_EQUAL(readonly_state.combined_layout, state.combined_layout);
  CHECK_EQUAL(readonly_state.name, state.name);
}

FIXTURE_SCOPE(foo, fixtures::deterministic_actor_system_and_events)

TEST(full partition roundtrip) {
  caf::scoped_actor actor(sys);
  auto fs = self->spawn<caf::detached>(vast::system::posix_filesystem, directory); // `directory` is provided by the unit test fixture
  sys.registry().put(vast::atom::filesystem_v, fs); 
  auto partition_uuid = vast::uuid::random();
  auto partition = sys.spawn(vast::system::v2::partition, partition_uuid);
  run();
  REQUIRE(partition);
  auto layout = vast::record_type{{"x", vast::count_type{}}}.name("y");
  vast::msgpack_table_slice_builder builder(layout);
  CHECK(builder.add(0u));
  auto slice = builder.finish();
  auto data = std::vector<vast::table_slice_ptr> {slice};
  vast::detail::spawn_container_source(sys, data, partition);
  run();
  // Persist the partition to disk;
  vast::path persist_path = "test-partition"; // will be interpreted relative to the fs actor's root dir
  // The standard `request/receive` leads to a deadlock here, not sure why but maybe some weird interaction
  // between blocking actors and response promises.
  actor->send(partition, vast::atom::persist_v, persist_path);
  run();
  actor->receive(
    [](vast::atom::ok) { CHECK("persisting done"); },
    [](caf::error err) { FAIL(err); });
  // Shut down partition.
  actor->send(partition, caf::error{});
  // Read persisted state from disk.
  vast::chunk_ptr chunk;
  actor->request(caf::actor_cast<vast::system::filesystem_type>(fs), caf::infinite, vast::atom::read_v, persist_path)
    .receive(
      [&](const vast::chunk_ptr& chk) {
        CHECK(chk);
        chunk = chk;
      },
      [&](const caf::error& err) { FAIL(err); });
  run();
  // Spawn a read-only partition from this chunk and try to query the data we added.
  // We make two queries, one "#type"-query and one "normal" query
  auto readonly_partition = sys.spawn(vast::system::v2::readonly_partition, partition_uuid, *chunk);
  REQUIRE(readonly_partition);
  // FIXME: This has the same weird deadlock when using request/receive, should probably be investigated.
  run();
  actor->send(readonly_partition, vast::atom::evaluate_v, vast::expression{vast::predicate{vast::field_extractor{".x"}, vast::equal, vast::data{0u}}});
  run();
  actor->receive(
    [](vast::evaluation_triples t) { CHECK_EQUAL(t.size(), 1u); },
    [](caf::error) { CHECK(false); });
  actor->send(readonly_partition, vast::atom::evaluate_v, vast::expression{vast::predicate{vast::field_extractor{".x"}, vast::equal, vast::data{23u}}});
  run();
  actor->receive(
    [](vast::evaluation_triples t) { CHECK_EQUAL(t.size(), 0u); },
    [](caf::error) { CHECK(false); });
  run();
  actor->send(readonly_partition, vast::atom::evaluate_v, vast::expression{vast::predicate{vast::attribute_extractor{vast::atom::type_v}, vast::equal, vast::data{"y.x"}}});
  run();
  actor->receive(
    [](vast::evaluation_triples t) { CHECK_EQUAL(t.size(), 1u); },
    [](caf::error) { CHECK(false); });
  run();
  // Shut down readonly_partition actor.
  CHECK(true);
  actor->send(readonly_partition, caf::error{});
}

FIXTURE_SCOPE_END()
