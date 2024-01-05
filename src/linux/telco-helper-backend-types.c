#include "telco-helper-backend.h"
#include "helpers/inject-context.h"

G_STATIC_ASSERT (sizeof (TelcoHelperBootstrapContext) == sizeof (TelcoBootstrapContext));
G_STATIC_ASSERT (sizeof (TelcoHelperLoaderContext) == sizeof (TelcoLoaderContext));
G_STATIC_ASSERT (sizeof (TelcoHelperLibcApi) == sizeof (TelcoLibcApi));
G_STATIC_ASSERT (sizeof (TelcoHelperByeMessage) == sizeof (TelcoByeMessage));
