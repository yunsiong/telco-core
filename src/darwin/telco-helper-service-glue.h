#ifndef __TELCO_HELPER_SERVICE_GLUE_H__
#define __TELCO_HELPER_SERVICE_GLUE_H__

#include <glib.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void _telco_start_run_loop (void);
G_GNUC_INTERNAL void _telco_stop_run_loop (void);

G_END_DECLS

#endif
