#include "inject-glue.h"

#include "telco-core.h"
#ifdef HAVE_ANDROID
# include "telco-selinux.h"
#endif

void
telco_inject_environment_init (void)
{
  telco_init_with_runtime (TELCO_RUNTIME_GLIB);

#ifdef HAVE_ANDROID
  telco_selinux_patch_policy ();
#endif
}
