#include "telco-helper-service-glue.h"

#include <windows.h>

#if GLIB_SIZEOF_VOID_P == 8
# define TELCO_HELPER_SERVICE_ARCH "64"
#else
# define TELCO_HELPER_SERVICE_ARCH "32"
#endif

#define STANDALONE_JOIN_TIMEOUT_MSEC (5 * 1000)

typedef struct _TelcoServiceContext TelcoServiceContext;

struct _TelcoServiceContext
{
  gchar * service_basename;

  SC_HANDLE scm;
  SC_HANDLE service32;
  SC_HANDLE service64;

  HANDLE standalone32;
  HANDLE standalone64;
};

static void WINAPI telco_managed_helper_service_main (DWORD argc, WCHAR ** argv);
static DWORD WINAPI telco_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context);
static void telco_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint);

static gboolean telco_register_and_start_services (TelcoServiceContext * self);
static void telco_stop_and_unregister_services (TelcoServiceContext * self);
static gboolean telco_spawn_standalone_services (TelcoServiceContext * self);
static gboolean telco_join_standalone_services (TelcoServiceContext * self);
static void telco_kill_standalone_services (TelcoServiceContext * self);
static void telco_release_standalone_services (TelcoServiceContext * self);

static gboolean telco_register_services (TelcoServiceContext * self);
static gboolean telco_unregister_services (TelcoServiceContext * self);
static gboolean telco_start_services (TelcoServiceContext * self);
static gboolean telco_stop_services (TelcoServiceContext * self);

static SC_HANDLE telco_register_service (TelcoServiceContext * self, const gchar * suffix);
static gboolean telco_unregister_service (TelcoServiceContext * self, SC_HANDLE handle);
static void telco_unregister_stale_services (TelcoServiceContext * self);
static gboolean telco_start_service (TelcoServiceContext * self, SC_HANDLE handle);
static gboolean telco_stop_service (TelcoServiceContext * self, SC_HANDLE handle);

static HANDLE telco_spawn_standalone_service (TelcoServiceContext * self, const gchar * suffix);
static gboolean telco_join_standalone_service (TelcoServiceContext * self, HANDLE handle);
static void telco_kill_standalone_service (TelcoServiceContext * self, HANDLE handle);

static TelcoServiceContext * telco_service_context_new (const gchar * service_basename);
static void telco_service_context_free (TelcoServiceContext * self);

static void telco_rmtree (GFile * file);

static WCHAR * telco_managed_helper_service_name = NULL;
static SERVICE_STATUS_HANDLE telco_managed_helper_service_status_handle = NULL;

void *
telco_helper_manager_start_services (const char * service_basename, TelcoPrivilegeLevel level)
{
  TelcoServiceContext * self;

  self = telco_service_context_new (service_basename);

  self->scm = (level == TELCO_PRIVILEGE_LEVEL_ELEVATED)
      ? OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS)
      : NULL;
  if (self->scm != NULL)
  {
    telco_unregister_stale_services (self);

    if (!telco_register_and_start_services (self))
    {
      CloseServiceHandle (self->scm);
      self->scm = NULL;
    }
  }

  if (self->scm == NULL)
  {
    if (!telco_spawn_standalone_services (self))
    {
      telco_service_context_free (self);
      self = NULL;
    }
  }

  return self;
}

void
telco_helper_manager_stop_services (void * context)
{
  TelcoServiceContext * self = context;

  if (self->scm != NULL)
  {
    telco_stop_and_unregister_services (self);
  }
  else
  {
    if (!telco_join_standalone_services (self))
      telco_kill_standalone_services (self);
  }

  telco_service_context_free (self);
}

char *
telco_helper_service_derive_basename (void)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);

  tmp = g_path_get_dirname (name);
  g_free (name);
  name = tmp;

  tmp = g_path_get_basename (name);
  g_free (name);
  name = tmp;

  tmp = g_strconcat (name, "-", NULL);
  g_free (name);
  name = tmp;

  return name;
}

char *
telco_helper_service_derive_filename_for_suffix (const char * suffix)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;
  glong len;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, &len, NULL);
  if (g_str_has_suffix (name, "-32.exe") || g_str_has_suffix (name, "-64.exe"))
  {
    name[len - 6] = '\0';
    tmp = g_strconcat (name, suffix, ".exe", NULL);
    g_free (name);
    name = tmp;
  }
  else
  {
    g_critical ("Unexpected filename: %s", name);
  }

  return name;
}

char *
telco_helper_service_derive_svcname_for_self (void)
{
  gchar * basename, * name;

  basename = telco_helper_service_derive_basename ();
  name = g_strconcat (basename, TELCO_HELPER_SERVICE_ARCH, NULL);
  g_free (basename);

  return name;
}

char *
telco_helper_service_derive_svcname_for_suffix (const char * suffix)
{
  gchar * basename, * name;

  basename = telco_helper_service_derive_basename ();
  name = g_strconcat (basename, suffix, NULL);
  g_free (basename);

  return name;
}

void
telco_managed_helper_service_enter_dispatcher_and_main_loop (void)
{
  SERVICE_TABLE_ENTRYW dispatch_table[2] = { 0, };
  gchar * name;

  name = telco_helper_service_derive_svcname_for_self ();
  telco_managed_helper_service_name = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);
  g_free (name);

  dispatch_table[0].lpServiceName = telco_managed_helper_service_name;
  dispatch_table[0].lpServiceProc = telco_managed_helper_service_main;

  StartServiceCtrlDispatcherW (dispatch_table);

  telco_managed_helper_service_status_handle = NULL;

  g_free (telco_managed_helper_service_name);
  telco_managed_helper_service_name = NULL;
}

static void WINAPI
telco_managed_helper_service_main (DWORD argc, WCHAR ** argv)
{
  GMainLoop * loop;

  (void) argc;
  (void) argv;

  loop = g_main_loop_new (NULL, FALSE);

  telco_managed_helper_service_status_handle = RegisterServiceCtrlHandlerExW (
      telco_managed_helper_service_name,
      telco_managed_helper_service_handle_control_code,
      loop);

  telco_managed_helper_service_report_status (SERVICE_START_PENDING, NO_ERROR, 0);

  telco_managed_helper_service_report_status (SERVICE_RUNNING, NO_ERROR, 0);
  g_main_loop_run (loop);
  telco_managed_helper_service_report_status (SERVICE_STOPPED, NO_ERROR, 0);

  g_main_loop_unref (loop);
}

static gboolean
telco_managed_helper_service_stop (gpointer data)
{
  GMainLoop * loop = data;

  g_main_loop_quit (loop);

  return FALSE;
}

static DWORD WINAPI
telco_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context)
{
  GMainLoop * loop = context;

  (void) event_type;
  (void) event_data;

  switch (control)
  {
    case SERVICE_CONTROL_STOP:
      telco_managed_helper_service_report_status (SERVICE_STOP_PENDING, NO_ERROR, 0);
      g_idle_add (telco_managed_helper_service_stop, loop);
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;

    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static void
telco_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
  SERVICE_STATUS status;
  static DWORD checkpoint = 1;

  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = current_state;

  if (current_state == SERVICE_START_PENDING)
    status.dwControlsAccepted = 0;
  else
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  status.dwWin32ExitCode = exit_code;
  status.dwServiceSpecificExitCode = 0;

  if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED)
  {
    status.dwCheckPoint = 0;
  }
  else
  {
    status.dwCheckPoint = checkpoint++;
  }

  status.dwWaitHint = wait_hint;

  SetServiceStatus (telco_managed_helper_service_status_handle, &status);
}

static gboolean
telco_register_and_start_services (TelcoServiceContext * self)
{
  if (!telco_register_services (self))
    return FALSE;

  if (!telco_start_services (self))
  {
    telco_unregister_services (self);
    return FALSE;
  }

  return TRUE;
}

static void
telco_stop_and_unregister_services (TelcoServiceContext * self)
{
  telco_stop_services (self);
  telco_unregister_services (self);
}

static gboolean
telco_spawn_standalone_services (TelcoServiceContext * self)
{
  HANDLE standalone32, standalone64;

  standalone32 = telco_spawn_standalone_service (self, "32");
  if (standalone32 == NULL)
    return FALSE;

  if (telco_windows_system_is_x64 ())
  {
    standalone64 = telco_spawn_standalone_service (self, "64");
    if (standalone64 == NULL)
    {
      telco_kill_standalone_service (self, standalone32);
      CloseHandle (standalone32);
      return FALSE;
    }
  }
  else
  {
    standalone64 = NULL;
  }

  self->standalone32 = standalone32;
  self->standalone64 = standalone64;

  return TRUE;
}

static gboolean
telco_join_standalone_services (TelcoServiceContext * self)
{
  gboolean success = TRUE;

  if (telco_windows_system_is_x64 ())
    success &= telco_join_standalone_service (self, self->standalone64);

  success &= telco_join_standalone_service (self, self->standalone32);

  if (success)
    telco_release_standalone_services (self);

  return success;
}

static void
telco_kill_standalone_services (TelcoServiceContext * self)
{
  if (telco_windows_system_is_x64 ())
    telco_kill_standalone_service (self, self->standalone64);

  telco_kill_standalone_service (self, self->standalone32);

  telco_release_standalone_services (self);
}

static void
telco_release_standalone_services (TelcoServiceContext * self)
{
  if (telco_windows_system_is_x64 ())
  {
    g_assert (self->standalone64 != NULL);
    CloseHandle (self->standalone64);
    self->standalone64 = NULL;
  }

  g_assert (self->standalone32 != NULL);
  CloseHandle (self->standalone32);
  self->standalone32 = NULL;
}

static gboolean
telco_register_services (TelcoServiceContext * self)
{
  SC_HANDLE service32, service64;

  service32 = telco_register_service (self, "32");
  if (service32 == NULL)
    return FALSE;

  if (telco_windows_system_is_x64 ())
  {
    service64 = telco_register_service (self, "64");
    if (service64 == NULL)
    {
      telco_unregister_service (self, service32);
      CloseServiceHandle (service32);
      return FALSE;
    }
  }
  else
  {
    service64 = NULL;
  }

  self->service32 = service32;
  self->service64 = service64;

  return TRUE;
}

static gboolean
telco_unregister_services (TelcoServiceContext * self)
{
  gboolean success = TRUE;

  if (telco_windows_system_is_x64 ())
  {
    success &= telco_unregister_service (self, self->service64);
    CloseServiceHandle (self->service64);
    self->service64 = NULL;
  }

  success &= telco_unregister_service (self, self->service32);
  CloseServiceHandle (self->service32);
  self->service32 = NULL;

  return success;
}

static gboolean
telco_start_services (TelcoServiceContext * self)
{
  if (!telco_start_service (self, self->service32))
    return FALSE;

  if (telco_windows_system_is_x64 ())
  {
    if (!telco_start_service (self, self->service64))
    {
      telco_stop_service (self, self->service32);
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
telco_stop_services (TelcoServiceContext * self)
{
  gboolean success = TRUE;

  if (telco_windows_system_is_x64 ())
    success &= telco_stop_service (self, self->service64);

  success &= telco_stop_service (self, self->service32);

  return success;
}

static SC_HANDLE
telco_register_service (TelcoServiceContext * self, const gchar * suffix)
{
  SC_HANDLE handle;
  gchar * servicename_utf8;
  WCHAR * servicename;
  gchar * displayname_utf8;
  WCHAR * displayname;
  gchar * filename_utf8;
  WCHAR * filename;

  servicename_utf8 = g_strconcat (self->service_basename, suffix, NULL);
  servicename = g_utf8_to_utf16 (servicename_utf8, -1, NULL, NULL, NULL);

  displayname_utf8 = g_strdup_printf ("Telco %s-bit helper (%s)", suffix, servicename_utf8);
  displayname = g_utf8_to_utf16 (displayname_utf8, -1, NULL, NULL, NULL);

  filename_utf8 = telco_helper_service_derive_filename_for_suffix (suffix);
  filename = g_utf8_to_utf16 (filename_utf8, -1, NULL, NULL, NULL);

  handle = CreateServiceW (self->scm,
      servicename,
      displayname,
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      filename,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);

  g_free (filename);
  g_free (filename_utf8);

  g_free (displayname);
  g_free (displayname_utf8);

  g_free (servicename);
  g_free (servicename_utf8);

  return handle;
}

static gboolean
telco_unregister_service (TelcoServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return DeleteService (handle);
}

static void
telco_unregister_stale_services (TelcoServiceContext * self)
{
  BYTE * services_data;
  DWORD services_size, bytes_needed, num_services, resume_handle;
  GQueue stale_services = G_QUEUE_INIT;

  services_size = 16384;
  services_data = g_malloc (services_size);

  resume_handle = 0;

  do
  {
    ENUM_SERVICE_STATUS_PROCESSW * services;
    DWORD i;

    num_services = 0;
    if (!EnumServicesStatusExW (self->scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_INACTIVE,
        services_data,
        services_size,
        &bytes_needed,
        &num_services,
        &resume_handle,
        NULL))
    {
      if (GetLastError () == ERROR_MORE_DATA)
      {
        if (num_services == 0)
        {
          services_data = g_realloc (services_data, bytes_needed);
          services_size = bytes_needed;
          continue;
        }
      }
      else
      {
        break;
      }
    }

    services = (ENUM_SERVICE_STATUS_PROCESSW *) services_data;
    for (i = 0; i != num_services; i++)
    {
      ENUM_SERVICE_STATUS_PROCESSW * service = &services[i];

      if (wcsncmp (service->lpServiceName, L"telco-", 6) == 0 && wcslen (service->lpServiceName) == 41)
      {
        SC_HANDLE handle = OpenServiceW (self->scm, service->lpServiceName, SERVICE_QUERY_CONFIG | DELETE);
        if (handle != NULL)
          g_queue_push_tail (&stale_services, handle);
      }
    }
  }
  while (num_services == 0 || resume_handle != 0);

  g_free (services_data);

  if (!g_queue_is_empty (&stale_services))
  {
    GHashTable * stale_dirs;
    QUERY_SERVICE_CONFIGW * config_data;
    DWORD config_size;
    GList * cur;
    GHashTableIter iter;
    gchar * stale_dir;

    stale_dirs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    config_data = NULL;
    config_size = 0;

    for (cur = stale_services.head; cur != NULL; cur = cur->next)
    {
      SC_HANDLE handle = cur->data;

retry:
      if (QueryServiceConfigW (handle, config_data, config_size, &bytes_needed))
      {
        gchar * binary_path, * tempdir_path;

        binary_path = g_utf16_to_utf8 (config_data->lpBinaryPathName, -1, NULL, NULL, NULL);
        tempdir_path = g_path_get_dirname (binary_path);

        g_hash_table_add (stale_dirs, tempdir_path);

        g_free (binary_path);
      }
      else if (GetLastError () == ERROR_INSUFFICIENT_BUFFER)
      {
        config_data = g_realloc (config_data, bytes_needed);
        config_size = bytes_needed;
        goto retry;
      }

      DeleteService (handle);
      CloseServiceHandle (handle);
    }

    g_hash_table_iter_init (&iter, stale_dirs);
    while (g_hash_table_iter_next (&iter, (gpointer *) &stale_dir, NULL))
    {
      GFile * file = g_file_new_for_path (stale_dir);
      telco_rmtree (file);
      g_object_unref (file);
    }

    g_free (config_data);
    g_hash_table_unref (stale_dirs);
  }

  g_queue_clear (&stale_services);
}

static gboolean
telco_start_service (TelcoServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return StartService (handle, 0, NULL);
}

static gboolean
telco_stop_service (TelcoServiceContext * self, SC_HANDLE handle)
{
  SERVICE_STATUS status = { 0, };

  (void) self;

  return ControlService (handle, SERVICE_CONTROL_STOP, &status);
}

static HANDLE
telco_spawn_standalone_service (TelcoServiceContext * self, const gchar * suffix)
{
  HANDLE handle = NULL;
  gchar * appname_utf8;
  WCHAR * appname;
  gchar * cmdline_utf8;
  WCHAR * cmdline;
  STARTUPINFOW si = { 0, };
  PROCESS_INFORMATION pi = { 0, };

  (void) self;

  appname_utf8 = telco_helper_service_derive_filename_for_suffix (suffix);
  appname = (WCHAR *) g_utf8_to_utf16 (appname_utf8, -1, NULL, NULL, NULL);

  cmdline_utf8 = g_strconcat ("\"", appname_utf8, "\" STANDALONE", NULL);
  cmdline = (WCHAR *) g_utf8_to_utf16 (cmdline_utf8, -1, NULL, NULL, NULL);

  si.cb = sizeof (si);

  if (CreateProcessW (appname, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
  {
    handle = pi.hProcess;
    CloseHandle (pi.hThread);
  }

  g_free (cmdline);
  g_free (cmdline_utf8);

  g_free (appname);
  g_free (appname_utf8);

  return handle;
}

static gboolean
telco_join_standalone_service (TelcoServiceContext * self, HANDLE handle)
{
  (void) self;

  return WaitForSingleObject (handle,
      STANDALONE_JOIN_TIMEOUT_MSEC) == WAIT_OBJECT_0;
}

static void
telco_kill_standalone_service (TelcoServiceContext * self, HANDLE handle)
{
  (void) self;

  TerminateProcess (handle, 1);
}

static TelcoServiceContext *
telco_service_context_new (const gchar * service_basename)
{
  TelcoServiceContext * self;

  self = g_slice_new0 (TelcoServiceContext);
  self->service_basename = g_strdup (service_basename);

  return self;
}

static void
telco_service_context_free (TelcoServiceContext * self)
{
  g_assert (self->standalone64 == NULL);
  g_assert (self->standalone32 == NULL);

  g_assert (self->service64 == NULL);
  g_assert (self->service32 == NULL);

  if (self->scm != NULL)
    CloseServiceHandle (self->scm);

  g_free (self->service_basename);

  g_slice_free (TelcoServiceContext, self);
}

static void
telco_rmtree (GFile * file)
{
  GFileEnumerator * enumerator =
      g_file_enumerate_children (file, G_FILE_ATTRIBUTE_STANDARD_NAME, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    GFileInfo * info;
    GFile * child;

    while (g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL) && child != NULL)
    {
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        telco_rmtree (child);
      else
        g_file_delete (child, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}
