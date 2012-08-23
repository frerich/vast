#include "vast/schema_manager.h"

#include "vast/schema.h"
#include "vast/logger.h"
#include "vast/to_string.h"

namespace vast {

schema_manager::schema_manager()
{
  LOG(verbose, meta) << "spawning schema manager @" << id();
  using namespace cppa;
  init_state = (
      on(atom("load"), arg_match) >> [=](std::string const& file)
      {
        schema_.read(file);
      },
      on(atom("schema")) >> [=]()
      {
        reply(schema_);
      },
      on(atom("shutdown")) >> [=]
      {
        quit();
        LOG(verbose, meta) << "schema manager @" << id() << " terminated";
      });
}

} // namespace vast
