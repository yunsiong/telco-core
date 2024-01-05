#include "telco-base.h"

#ifdef HAVE_WINDOWS
# include <winsock2.h>
#else
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif

void
telco_unix_socket_tune_buffer_sizes (gint fd)
{
#ifndef HAVE_WINDOWS
  /* The defaults are typically as low as 4K. */
  const int buffer_size = 256 * 1024;

  setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof (buffer_size));
  setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof (buffer_size));
#endif
}

void
telco_tcp_enable_nodelay (GSocket * socket)
{
  g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);
}

const gchar *
_telco_version_string (void)
{
  return TELCO_VERSION;
}
