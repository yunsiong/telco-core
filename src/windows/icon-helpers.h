#ifndef __TELCO_WINDOWS_ICON_HELPERS_H__
#define __TELCO_WINDOWS_ICON_HELPERS_H__

#include "telco-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _TelcoIconSize TelcoIconSize;

enum _TelcoIconSize
{
  TELCO_ICON_SMALL,
  TELCO_ICON_LARGE
};

GVariant * _telco_icon_from_process_or_file (DWORD pid, WCHAR * filename, TelcoIconSize size);

GVariant * _telco_icon_from_process (DWORD pid, TelcoIconSize size);
GVariant * _telco_icon_from_file (WCHAR * filename, TelcoIconSize size);
GVariant * _telco_icon_from_resource_url (WCHAR * resource_url, TelcoIconSize size);

GVariant * _telco_icon_from_native_icon_handle (HICON icon, TelcoIconSize size);

#endif
