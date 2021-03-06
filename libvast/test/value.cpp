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

#define SUITE value

#include "vast/test/test.hpp"

#include "vast/load.hpp"
#include "vast/json.hpp"
#include "vast/save.hpp"
#include "vast/value.hpp"
#include "vast/concept/convertible/to.hpp"
#include "vast/concept/parseable/to.hpp"
#include "vast/concept/parseable/vast/data.hpp"
#include "vast/concept/printable/to_string.hpp"
#include "vast/concept/printable/vast/json.hpp"
#include "vast/concept/printable/vast/value.hpp"

using caf::get;
using caf::get_if;
using caf::holds_alternative;

using namespace vast;

// An *invalid* value has neither a type nor data.
// This is the default-constructed state.
TEST(invalid) {
  value v;
  CHECK(holds_alternative<caf::none_t>(v));
  CHECK(!v.type());
}

// A *data* value contains only data but lacks a type.
TEST(data value) {
  value v{42};
  CHECK(type_check(v.type(), data{caf::none}));
  CHECK(holds_alternative<integer>(v));
  CHECK(!v.type());
}

TEST(typed value(empty)) {
  type t = count_type{};
  value v{caf::none, t};
  CHECK(type_check(t, data{caf::none}));
  CHECK(v.type() == t);
  CHECK(holds_alternative<caf::none_t>(v));
  CHECK(holds_alternative<count_type>(v.type()));
}

TEST(typed value(data)) {
  type t = real_type{};
  value v{4.2, t};
  CHECK(type_check(t, data{4.2}));
  CHECK(v.type() == t);
  CHECK(holds_alternative<real>(v));
  CHECK(holds_alternative<real_type>(v.type()));
}

TEST(data and type mismatch) {
  // This value has a data and type mismatch. For performance reasons, the
  // constructor will *not* perform a type check.
  value v{42, real_type{}};
  CHECK(v.data() == 42);
  CHECK(v.type() == real_type{});
  // If we do require type safety and cannot guarantee that data and type
  // match, we can use the type-safe factory function.
  auto fail = value::make(42, real_type{});
  CHECK(holds_alternative<caf::none_t>(fail));
  CHECK(!fail.type());
}

TEST(relational operators) {
  value v1;
  value v2;

  MESSAGE("comparison of nil values");
  CHECK(v1 == v2);
  type t = real_type{};

  MESSAGE("typed value with equal data");
  v1 = {4.2, t};
  v2 = {4.2, t};
  CHECK(type_check(t, data{4.2}));
  CHECK(v1 == v2);
  CHECK(!(v1 != v2));
  CHECK(!(v1 < v2));
  CHECK(v1 <= v2);
  CHECK(v1 >= v2);
  CHECK(!(v1 > v2));

  MESSAGE("different data, same type");
  v2 = {4.3, t};
  CHECK(v1 != v2);
  CHECK(!(v1 == v2));
  CHECK(v1 < v2);

  MESSAGE("no type, but data comparison still works");
  v2 = 4.2;
  CHECK(v1 == v2);

  MESSAGE("compares only data");
  v1 = 4.2;
  CHECK(v1 == v2);
  v1 = -4.2;
  CHECK(v1 != v2);
  CHECK(v1 < v2);
}

TEST(serialization) {
  type t = list_type{port_type{}};
  list xs;
  xs.emplace_back(port{80, port::tcp});
  xs.emplace_back(port{53, port::udp});
  xs.emplace_back(port{8, port::icmp});
  CHECK(type_check(t, data{xs}));
  value v{xs, t};
  value w;
  std::vector<char> buf;
  CHECK_EQUAL(save(nullptr, buf, v), caf::none);
  CHECK_EQUAL(load(nullptr, buf, w), caf::none);
  CHECK(v == w);
  CHECK(to_string(w) == "[80/tcp, 53/udp, 8/icmp]");
}

TEST(json)
{
  auto t =
    record_type{
      {"foo", port_type{}},
      {"bar", integer_type{}},
      {"baz", real_type{}}
    };
  auto d = to<data>("[53/udp,-42,4.2]");
  REQUIRE(d);
  auto v = value{*d, t};
  auto j = to<json>(v);
  REQUIRE(j);
  auto str = R"__({
  "foo": 53,
  "bar": -42,
  "baz": 4.2
})__";
  CHECK_EQUAL(to_string(*j), str);
}
