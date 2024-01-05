#include "telco-core.h"

GBytes *
_telco_agent_descriptor_clone_so (GBytes * so)
{
  /* TODO: update .so identity */
  return g_bytes_ref (so);
}
