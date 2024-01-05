#ifndef __TELCO_HELPER_PROCESS_GLUE_H__
#define __TELCO_HELPER_PROCESS_GLUE_H__

#include "telco-helper-backend.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void * telco_helper_factory_spawn (const gchar * path, const gchar * parameters, TelcoPrivilegeLevel level,
    GError ** error);

G_GNUC_INTERNAL gboolean telco_helper_instance_is_process_still_running (void * handle);
G_GNUC_INTERNAL void telco_helper_instance_close_process_handle (void * handle);

G_END_DECLS

#endif
