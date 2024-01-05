#include "telco-core.h"

#include "telco-base.h"

void
_telco_fruity_host_session_backend_extract_details_for_device (gint product_id, const char * udid, char ** name, GVariant ** icon,
    GError ** error)
{
  *name = g_strdup ("iOS Device");
  *icon = NULL;
}
