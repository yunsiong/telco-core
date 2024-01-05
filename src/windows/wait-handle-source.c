#include "telco-helper-backend.h"

#include <windows.h>

#define TELCO_WAIT_HANDLE_SOURCE(s) ((TelcoWaitHandleSource *) (s))

typedef struct _TelcoWaitHandleSource TelcoWaitHandleSource;

struct _TelcoWaitHandleSource
{
  GSource source;

  HANDLE handle;
  gboolean owns_handle;
  GPollFD handle_poll_fd;
};

static void telco_wait_handle_source_finalize (GSource * source);

static gboolean telco_wait_handle_source_prepare (GSource * source,
    gint * timeout);
static gboolean telco_wait_handle_source_check (GSource * source);
static gboolean telco_wait_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

static GSourceFuncs telco_wait_handle_source_funcs = {
  telco_wait_handle_source_prepare,
  telco_wait_handle_source_check,
  telco_wait_handle_source_dispatch,
  telco_wait_handle_source_finalize
};

GSource *
telco_wait_handle_source_create (void * handle, gboolean owns_handle)
{
  GSource * source;
  GPollFD * pfd;
  TelcoWaitHandleSource * whsrc;

  source = g_source_new (&telco_wait_handle_source_funcs,
      sizeof (TelcoWaitHandleSource));
  whsrc = TELCO_WAIT_HANDLE_SOURCE (source);
  whsrc->handle = handle;
  whsrc->owns_handle = owns_handle;

  pfd = &TELCO_WAIT_HANDLE_SOURCE (source)->handle_poll_fd;
#if GLIB_SIZEOF_VOID_P == 8
  pfd->fd = (gint64) handle;
#else
  pfd->fd = (gint) handle;
#endif
  pfd->events = G_IO_IN | G_IO_OUT | G_IO_HUP | G_IO_ERR;
  pfd->revents = 0;
  g_source_add_poll (source, pfd);

  return source;
}

static void
telco_wait_handle_source_finalize (GSource * source)
{
  TelcoWaitHandleSource * self = TELCO_WAIT_HANDLE_SOURCE (source);

  if (self->owns_handle)
    CloseHandle (self->handle);
}

static gboolean
telco_wait_handle_source_prepare (GSource * source, gint * timeout)
{
  TelcoWaitHandleSource * self = TELCO_WAIT_HANDLE_SOURCE (source);

  *timeout = -1;

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
telco_wait_handle_source_check (GSource * source)
{
  TelcoWaitHandleSource * self = TELCO_WAIT_HANDLE_SOURCE (source);

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
telco_wait_handle_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  g_assert (WaitForSingleObject (TELCO_WAIT_HANDLE_SOURCE (source)->handle, 0) == WAIT_OBJECT_0);

  return callback (user_data);
}
