#ifndef __TELCO_DARWIN_ICON_HELPERS_H__
#define __TELCO_DARWIN_ICON_HELPERS_H__

#include "telco-core.h"

typedef gpointer TelcoNativeImage;

GVariant * _telco_icon_from_file (const gchar * filename, guint target_width, guint target_height);
GVariant * _telco_icon_from_native_image_scaled_to (TelcoNativeImage native_image, guint target_width, guint target_height);

#endif
