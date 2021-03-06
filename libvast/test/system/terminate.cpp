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

#include "vast/system/terminate.hpp"

#include "vast/fwd.hpp"

#include <caf/behavior.hpp>
#include <caf/event_based_actor.hpp>

#define SUITE terminator
#include "vast/test/fixtures/actor_system.hpp"
#include "vast/test/test.hpp"

using namespace vast;
using namespace vast::system;

namespace {

caf::behavior worker(caf::event_based_actor* self) {
  return [=](atom::done) { self->quit(); };
}

struct fixture : fixtures::actor_system {
  fixture() {
    victims = std::vector<caf::actor>{sys.spawn(worker), sys.spawn(worker),
                                      sys.spawn(worker)};
  }

  std::vector<caf::actor> victims;
};

} // namespace

FIXTURE_SCOPE(terminate_tests, fixture)

TEST(parallel shutdown) {
  terminate<policy::parallel>(self, victims)
    .receive([&](atom::done) { /* */ },
             [&](const caf::error& err) { FAIL(err); });
}

TEST(sequential shutdown) {
  terminate<policy::sequential>(self, victims)
    .receive([&](atom::done) { /* */ },
             [&](const caf::error& err) { FAIL(err); });
}

FIXTURE_SCOPE_END()
