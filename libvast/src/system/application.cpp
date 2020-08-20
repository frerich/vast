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

#include "vast/system/application.hpp"

#include "vast/command.hpp"
#include "vast/config.hpp"
#include "vast/detail/assert.hpp"
#include "vast/detail/process.hpp"
#include "vast/documentation.hpp"
#include "vast/format/ascii.hpp"
#include "vast/format/csv.hpp"
#include "vast/format/json.hpp"
#include "vast/format/json/suricata.hpp"
#include "vast/format/null.hpp"
#include "vast/format/syslog.hpp"
#include "vast/format/test.hpp"
#include "vast/format/zeek.hpp"
#include "vast/system/configuration.hpp"
#include "vast/system/count_command.hpp"
#include "vast/system/explore_command.hpp"
#include "vast/system/import_command.hpp"
#include "vast/system/infer_command.hpp"
#include "vast/system/pivot_command.hpp"
#include "vast/system/remote_command.hpp"
#include "vast/system/start_command.hpp"
#include "vast/system/stop_command.hpp"
#include "vast/system/version_command.hpp"
#include "vast/system/writer_command.hpp"

#if VAST_HAVE_ARROW
#  include "vast/format/arrow.hpp"
#endif

#if VAST_HAVE_PCAP
#  include "vast/format/pcap.hpp"
#  include "vast/system/pcap_writer_command.hpp"
#endif

namespace vast::system {

namespace {

auto make_pcap_options(std::string_view category) {
  return sink_opts(category).add<size_t>(
    "flush-interval,f", "flush to disk after this many packets");
}

command::opts_builder add_index_opts(command::opts_builder ob) {
  return std::move(ob)
    .add<size_t>("max-partition-size", "maximum number of events in a "
                                       "partition")
    .add<size_t>("max-resident-partitions", "maximum number of in-memory "
                                            "partitions")
    .add<size_t>("max-taste-partitions", "maximum number of immediately "
                                         "scheduled partitions")
    .add<size_t>("max-queries,q", "maximum number of concurrent queries");
}

auto make_root_command(std::string_view path) {
  // We're only interested in the application name, not in its path. For
  // example, argv[0] might contain "./build/release/bin/vast" and we are only
  // interested in "vast".
  path.remove_prefix(std::min(path.find_last_of('/') + 1, path.size()));
  // For documentation, we use the complete man-page formatted as Markdown
  auto binary = detail::objectpath();
  auto schema_desc
    = "list of paths to look for schema files ([/etc/vast/schema"s;
  if (binary) {
    auto relative_schema_dir
      = binary->parent().parent() / "share" / "vast" / "schema";
    schema_desc += ", " + relative_schema_dir.str();
  }
  schema_desc += "])";
  auto ob
    = opts("?system")
        .add<std::string>("config", "path to a configuration file")
        .add<caf::atom_value>("verbosity,v", "output verbosity level on the "
                                             "console")
        .add<std::vector<std::string>>("schema-paths", schema_desc.c_str())
        .add<std::string>("db-directory,d", "directory for persistent state")
        .add<std::string>("log-file", "log filename")
        .add<std::string>("endpoint,e", "node endpoint")
        .add<std::string>("node-id,i", "the unique ID of this node")
        .add<bool>("node,N", "spawn a node instead of connecting to one")
        .add<bool>("disable-metrics", "don't keep track of performance metrics")
        .add<bool>("no-default-schema", "don't load the default schema "
                                        "definitions")
        .add<std::string>("aging-frequency", "interval between two aging "
                                             "cycles")
        .add<std::string>("aging-query", "query for aging out obsolete data");
  return std::make_unique<command>(path, "", documentation::vast,
                                   add_index_opts(std::move(ob)));
}

auto make_count_command() {
  return std::make_unique<command>(
    "count", "count hits for a query without exporting data", "",
    opts("?count").add<bool>("estimate,e", "estimate an upper bound by "
                                           "skipping candidate checks"));
}

auto make_explore_command() {
  return std::make_unique<command>(
    "explore", "explore context around query results",
    documentation::vast_explore,
    opts("?explore")
      .add<std::string>("format", "output format (default: JSON)")
      .add<std::string>("after,A", "include all records up to this much"
                                   " time after each result")
      .add<std::string>("before,B", "include all records up to this much"
                                    " time before each result")
      .add<std::string>("by", "perform an equijoin on the given field")
      .add<count>("max-events,n", "maximum number of results")
      .add<count>("max-events-query", "maximum results for initial query")
      .add<count>("max-events-context", "maximum results per exploration"));
}

auto make_export_command() {
  auto export_ = std::make_unique<command>(
    "export", "exports query results to STDOUT or file",
    documentation::vast_export,
    opts("?export")
      .add<bool>("continuous,c", "marks a query as continuous")
      .add<bool>("unified,u", "marks a query as unified")
      .add<size_t>("max-events,n", "maximum number of results")
      .add<std::string>("read,r", "path for reading the query"));
  export_->add_subcommand("zeek", "exports query results in Zeek format",
                          documentation::vast_export_zeek,
                          sink_opts("?export.zeek"));
  export_->add_subcommand("csv", "exports query results in CSV format",
                          documentation::vast_export_csv,
                          sink_opts("?export.csv"));
  export_->add_subcommand("ascii", "exports query results in ASCII format",
                          documentation::vast_export_ascii,
                          sink_opts("?export.ascii"));
  export_->add_subcommand("json", "exports query results in JSON format",
                          documentation::vast_export_json,
                          sink_opts("?export.json"));
  export_->add_subcommand("null",
                          "exports query without printing them (debug option)",
                          documentation::vast_export_null,
                          sink_opts("?export.null"));
#if VAST_HAVE_ARROW
  export_->add_subcommand("arrow", "exports query results in Arrow format",
                          documentation::vast_export_arrow,
                          sink_opts("?export.arrow"));

#endif
#if VAST_HAVE_PCAP
  export_->add_subcommand("pcap", "exports query results in PCAP format",
                          documentation::vast_export_pcap,
                          make_pcap_options("?export.pcap"));
#endif
  return export_;
}

auto make_infer_command() {
  return std::make_unique<command>(
    "infer", "infers the schema from data", documentation::vast_infer,
    opts("?infer")
      .add<size_t>("buffer,b", "maximum number of bytes to buffer")
      .add<std::string>("read,r", "path to the input data"));
}

auto make_import_command() {
  auto import_ = std::make_unique<command>(
    "import", "imports data from STDIN or file", documentation::vast_import,
    opts("?import")
      .add<caf::atom_value>("table-slice-type,t", "table slice type")
      .add<size_t>("table-slice-size,s", "the suggested size for table slices")
      .add<bool>("blocking,b", "block until the IMPORTER forwarded all data")
      .add<size_t>("max-events,n", "the maximum number of events to "
                                   "import")
      .add<std::string>("read-timeout", "read timoeut after which data is "
                                        "forwarded to the importer"));
  import_->add_subcommand("zeek", "imports Zeek logs from STDIN or file",
                          documentation::vast_import_zeek,
                          source_opts("?import.zeek"));
  import_->add_subcommand("csv", "imports CSV logs from STDIN or file",
                          documentation::vast_import_csv,
                          source_opts("?import.csv"));
  import_->add_subcommand("json", "imports JSON with schema",
                          documentation::vast_import_json,
                          source_opts("?import.json"));
  import_->add_subcommand("suricata", "imports suricata eve json",
                          documentation::vast_import_suricata,
                          source_opts("?import.suricata"));
  import_->add_subcommand("syslog", "imports syslog messages",
                          documentation::vast_import_syslog,
                          source_opts("?import.syslog"));
  import_->add_subcommand(
    "test", "imports random data for testing or benchmarking",
    documentation::vast_import_test,
    source_opts("?import.test").add<size_t>("seed", "the PRNG seed"));
#if VAST_HAVE_PCAP
  import_->add_subcommand(
    "pcap", "imports PCAP logs from STDIN or file",
    documentation::vast_import_pcap,
    source_opts("?import.pcap")
      .add<std::string>("interface,i", "network interface to read packets from")
      .add<size_t>("cutoff,c", "skip flow packets after this many bytes")
      .add<size_t>("max-flows,m", "number of concurrent flows to track")
      .add<size_t>("max-flow-age,a", "max flow lifetime before eviction")
      .add<size_t>("flow-expiry,e", "flow table expiration interval")
      .add<size_t>("pseudo-realtime-factor,p", "factor c delaying packets by "
                                               "1/c")
      .add<size_t>("snaplen", "snapshot length in bytes")
      .add<double>("drop-rate-threshold", "drop rate that must be exceeded for "
                                          "warnings to occur")
      .add<bool>("disable-community-id", "disable computation of community id "
                                         "for every packet"));
#endif
  return import_;
}

auto make_kill_command() {
  return std::make_unique<command>("kill", "terminates a component", "", opts(),
                                   false);
}

auto make_peer_command() {
  return std::make_unique<command>("peer", "peers with another node", "",
                                   opts(), false);
}

auto make_pivot_command() {
  auto pivot = std::make_unique<command>(
    "pivot", "extracts related events of a given type",
    documentation::vast_pivot,
    make_pcap_options("?pivot").add<std::string>("format", "output format "
                                                           "(default: JSON)"));
  return pivot;
}

auto make_send_command() {
  return std::make_unique<command>(
    "send", "sends a message to a registered actor", "", opts(), false);
}

auto make_spawn_source_command() {
  auto spawn_source = std::make_unique<command>(
    "source", "creates a new source inside the node",
    documentation::vast_spawn_source,
    opts("?spawn.source")
      .add<caf::atom_value>("table-slice-type,t", "table slice type")
      .add<size_t>("table-slice-size,s", "the suggested size for table slices")
      .add<size_t>("max-events,n", "the maximum number of events to "
                                   "import")
      .add<std::string>("read-timeout", "read timoeut after which data is "
                                        "forwarded to the importer"));
  spawn_source->add_subcommand("csv",
                               "creates a new CSV source inside the node",
                               documentation::vast_spawn_source_csv,
                               source_opts("?spawn.source.csv"));
  spawn_source->add_subcommand("json",
                               "creates a new JSON source inside the node",
                               documentation::vast_spawn_source_json,
                               source_opts("?spawn.source.json"));
#if VAST_HAVE_PCAP
  spawn_source->add_subcommand(
    "pcap", "creates a new PCAP source inside the node",
    documentation::vast_spawn_source_pcap,
    source_opts("?spawn.source.pcap")
      .add<std::string>("interface,i", "network interface to read packets from")
      .add<size_t>("cutoff,c", "skip flow packets after this many bytes")
      .add<size_t>("max-flows,m", "number of concurrent flows to track")
      .add<size_t>("max-flow-age,a", "max flow lifetime before eviction")
      .add<size_t>("flow-expiry,e", "flow table expiration interval")
      .add<size_t>("pseudo-realtime-factor,p", "factor c delaying packets by "
                                               "1/c")
      .add<size_t>("snaplen", "snapshot length in bytes")
      .add<double>("drop-rate-threshold", "drop rate that must be exceeded for "
                                          "warnings to occur")
      .add<bool>("disable-community-id", "disable computation of community id "
                                         "for every packet"));
#endif
  spawn_source->add_subcommand("suricata",
                               "creates a new Suricata source inside the node",
                               documentation::vast_spawn_source_suricata,
                               source_opts("?spawn.source.suricata"));
  spawn_source->add_subcommand("syslog",
                               "creates a new Syslog source inside the node",
                               documentation::vast_spawn_source_syslog,
                               source_opts("?spawn.source.syslog"));
  spawn_source->add_subcommand(
    "test", "creates a new test source inside the node",
    documentation::vast_spawn_source_test,
    source_opts("?spawn.source.test").add<size_t>("seed", "the PRNG seed"));
  spawn_source->add_subcommand("zeek",
                               "creates a new Zeek source inside the node",
                               documentation::vast_spawn_source_zeek,
                               source_opts("?spawn.source.zeek"));
  return spawn_source;
}

auto make_spawn_sink_command() {
  auto spawn_sink = std::make_unique<command>(
    "sink", "creates a new sink", "",
    opts()
      .add<std::string>("write,w", "path to write events to")
      .add<bool>("uds,d", "treat -w as UNIX domain socket"),
    false);
  spawn_sink->add_subcommand(
    "pcap", "creates a new PCAP sink", "",
    opts().add<size_t>("flush,f", "flush to disk after this many packets"));
  spawn_sink->add_subcommand("zeek", "creates a new Zeek sink", "", opts());
  spawn_sink->add_subcommand("ascii", "creates a new ASCII sink", "", opts());
  spawn_sink->add_subcommand("csv", "creates a new CSV sink", "", opts());
  spawn_sink->add_subcommand("json", "creates a new JSON sink", "", opts());
  return spawn_sink;
}

auto make_spawn_command() {
  auto spawn = std::make_unique<command>("spawn", "creates a new component",
                                         documentation::vast_spawn, opts());
  spawn->add_subcommand("accountant", "spawns the accountant", "", opts(),
                        false);
  spawn->add_subcommand(
    "archive", "creates a new archive", "",
    opts()
      .add<size_t>("segments,s", "number of cached segments")
      .add<size_t>("max-segment-size,m", "maximum segment size in MB"),
    false);
  spawn->add_subcommand(
    "explorer", "creates a new explorer", "",
    opts()
      .add<vast::duration>("after,A", "timebox after each result")
      .add<vast::duration>("before,B", "timebox before each result"),
    false);
  spawn->add_subcommand(
    "exporter", "creates a new exporter", "",
    opts()
      .add<bool>("continuous,c", "marks a query as continuous")
      .add<bool>("unified,u", "marks a query as unified")
      .add<uint64_t>("events,e", "maximum number of results"),
    false);
  spawn->add_subcommand("importer", "creates a new importer", "",
                        opts().add<size_t>("ids,n", "number of initial IDs to "
                                                    "request (deprecated)"),
                        false);
  spawn->add_subcommand("index", "creates a new index", "",
                        add_index_opts(opts()), false);
  spawn->add_subcommand(make_spawn_source_command());
  spawn->add_subcommand(make_spawn_sink_command());
  return spawn;
}

auto make_status_command() {
  return std::make_unique<command>(
    "status", "shows various properties of a topology",
    documentation::vast_status,
    opts().add<caf::atom_value>("verbosity,v", "output verbosity level"));
}

auto make_start_command() {
  return std::make_unique<command>("start", "starts a node",
                                   documentation::vast_start, opts());
}

auto make_stop_command() {
  return std::make_unique<command>("stop", "stops a node",
                                   documentation::vast_stop, opts());
}

auto make_version_command() {
  return std::make_unique<command>("version", "prints the software version",
                                   documentation::vast_version, opts());
}

auto make_command_factory() {
  // When updating this list, remember to update its counterpart in node.cpp as
  // well iff necessary
  // clang-format off
  return command::factory{
    {"count", count_command},
    {"explore", explore_command},
    {"export ascii", writer_command<format::ascii::writer>},
    {"export csv", writer_command<format::csv::writer>},
    {"export json", writer_command<format::json::writer>},
    {"export null", writer_command<format::null::writer>},
#if VAST_HAVE_ARROW
    {"export arrow", writer_command<format::arrow::writer>},
#endif
#if VAST_HAVE_PCAP
    {"export pcap", pcap_writer_command},
#endif
    {"export zeek", writer_command<format::zeek::writer>},
    {"infer", infer_command},
    {"import csv", import_command<format::csv::reader, defaults::import::csv>},
    {"import json", import_command<format::json::reader<>,
      defaults::import::json>},
#if VAST_HAVE_PCAP
    {"import pcap", import_command<format::pcap::reader,
      defaults::import::pcap>},
#endif
    {"import suricata", import_command<
      format::json::reader<format::json::suricata>,
      defaults::import::suricata>},
    {"import syslog", import_command<format::syslog::reader,
      defaults::import::syslog>},
    {"import test", import_command<format::test::reader,
      defaults::import::test>},
    {"import zeek", import_command<format::zeek::reader,
      defaults::import::zeek>},
    {"kill", remote_command},
    {"peer", remote_command},
    {"pivot", pivot_command},
    {"send", remote_command},
    {"spawn accountant", remote_command},
    {"spawn archive", remote_command},
    {"spawn eraser", remote_command},
    {"spawn exporter", remote_command},
    {"spawn explorer", remote_command},
    {"spawn importer", remote_command},
    {"spawn type-registry", remote_command},
    {"spawn index", remote_command},
    {"spawn sink ascii", remote_command},
    {"spawn sink csv", remote_command},
    {"spawn sink json", remote_command},
    {"spawn sink pcap", remote_command},
    {"spawn sink zeek", remote_command},
    {"spawn source csv", remote_command},
    {"spawn source json", remote_command},
    {"spawn source pcap", remote_command},
    {"spawn source suricata", remote_command},
    {"spawn source syslog", remote_command},
    {"spawn source test", remote_command},
    {"spawn source zeek", remote_command},
    {"start", start_command},
    {"status", remote_command},
    {"stop", stop_command},
    {"version", version_command},
  };
  // clang-format on
}

} // namespace

std::pair<std::unique_ptr<command>, command::factory>
make_application(std::string_view path) {
  auto root = make_root_command(path);
  root->add_subcommand(make_count_command());
  root->add_subcommand(make_export_command());
  root->add_subcommand(make_explore_command());
  root->add_subcommand(make_infer_command());
  root->add_subcommand(make_import_command());
  root->add_subcommand(make_kill_command());
  root->add_subcommand(make_peer_command());
  root->add_subcommand(make_pivot_command());
  root->add_subcommand(make_send_command());
  root->add_subcommand(make_spawn_command());
  root->add_subcommand(make_start_command());
  root->add_subcommand(make_status_command());
  root->add_subcommand(make_stop_command());
  root->add_subcommand(make_version_command());
  return {std::move(root), make_command_factory()};
}

void render_error(const command& root, const caf::error& err,
                  std::ostream& os) {
  if (!err)
    // The user most likely killed the process via CTRL+C, print nothing.
    return;
  os << render(err) << '\n';
  if (err.category() == caf::atom("vast")) {
    auto x = static_cast<vast::ec>(err.code());
    switch (x) {
      default:
        break;
      case ec::invalid_subcommand:
      case ec::missing_subcommand:
      case ec::unrecognized_option: {
        auto ctx = err.context();
        if (ctx.match_element<std::string>(1)) {
          auto name = ctx.get_as<std::string>(1);
          if (auto cmd = resolve(root, name))
            helptext(*cmd, os);
        } else {
          VAST_ASSERT(!"User visible error contexts must consist of strings!");
        }
        break;
      }
    }
  }
}

command::opts_builder source_opts(std::string_view category) {
  return command::opts(category)
    .add<std::string>("listen,l", "the endpoint to listen on "
                                  "([host]:port/type)")
    .add<std::string>("read,r", "path to input where to read events from")
    .add<std::string>("schema-file,s", "path to alternate schema")
    .add<std::string>("schema,S", "alternate schema as string")
    .add<std::string>("type,t", "filter event type based on prefix matching")
    .add<bool>("uds,d", "treat -r as listening UNIX domain socket");
}

command::opts_builder sink_opts(std::string_view category) {
  return command::opts(category)
    .add<std::string>("write,w", "path to write events to")
    .add<bool>("uds,d", "treat -w as UNIX domain socket to connect to");
}

command::opts_builder opts(std::string_view category) {
  return command::opts(category);
}

} // namespace vast::system
