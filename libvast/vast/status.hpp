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

#include <caf/config_value.hpp>
#include <caf/dictionary.hpp>

namespace vast {

enum class status_verbosity { info, verbose, debug };

struct status {
  caf::dictionary<caf::config_value> info;
  caf::dictionary<caf::config_value> verbose;
  caf::dictionary<caf::config_value> debug;
};

caf::dictionary<caf::config_value> join(const status& s);

} // namespace vast
