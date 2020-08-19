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

#include "vast/detail/fill_status_map.hpp"

#include <caf/config_value.hpp>
#include <caf/downstream_manager.hpp>
#include <caf/inbound_path.hpp>
#include <caf/outbound_path.hpp>
#include <caf/scheduled_actor.hpp>
#include <caf/settings.hpp>
#include <caf/stream_manager.hpp>

#include "vast/detail/algorithms.hpp"

namespace vast::detail {

void fill_status_map(caf::settings& xs, caf::stream_manager& mgr) {
  // Manager status.
  put(xs, "idle", mgr.idle());
  put(xs, "congested", mgr.congested());
  // Downstream status.
  auto& out = mgr.out();
  auto& downstream = put_dictionary(xs, "downstream");
  put(downstream, "buffered", out.buffered());
  put(downstream, "max-capacity", out.max_capacity());
  put(downstream, "paths", out.num_paths());
  put(downstream, "stalled", out.stalled());
  put(downstream, "clean", out.clean());
  out.for_each_path([&](auto& opath) {
    auto name = "slot-" + std::to_string(opath.slots.sender);
    auto& slot = put_dictionary(downstream, name);
    put(slot, "pending", opath.pending());
    put(slot, "clean", opath.clean());
    put(slot, "closing", opath.closing);
    put(slot, "next-batch-id", opath.next_batch_id);
    put(slot, "open-credit", opath.open_credit);
    put(slot, "desired-batch-size", opath.desired_batch_size);
    put(slot, "max-capacity", opath.max_capacity);
  });
  // Upstream status.
  auto& upstream = put_dictionary(xs, "upstream");
  auto& ipaths = mgr.inbound_paths();
  if (!ipaths.empty())
    put(xs, "inbound-paths-idle", mgr.inbound_paths_idle());
  for (auto ipath : ipaths) {
    auto name = "slot-" + std::to_string(ipath->slots.receiver);
    auto& slot = put_dictionary(upstream, name);
    put(slot, "priority", to_string(ipath->prio));
    put(slot, "assigned-credit", ipath->assigned_credit);
    put(slot, "last-acked-batch-id", ipath->last_acked_batch_id);
  }
}

void fill_status_map(caf::dictionary<caf::config_value>& dict,
                     caf::scheduled_actor* self) {
  auto& xs = caf::put_dictionary(dict, self->name());
  put(xs, "actor-id", self->id());
  put(xs, "name", self->name());
  put(xs, "mailbox-size", self->mailbox().size());
  size_t counter = 0;
  std::string name;
  for (auto& mgr : unique_values(self->stream_managers())) {
    name = "stream-";
    name += std::to_string(counter++);
    fill_status_map(put_dictionary(xs, name), *mgr);
  }
}

} // namespace vast::detail
