#include "inject-context.h"
#include "syscall.h"

#include <alloca.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif

typedef int TelcoUnloadPolicy;
typedef struct _TelcoLinuxInjectorState TelcoLinuxInjectorState;
typedef union _TelcoControlMessage TelcoControlMessage;

enum _TelcoUnloadPolicy
{
  TELCO_UNLOAD_POLICY_IMMEDIATE,
  TELCO_UNLOAD_POLICY_RESIDENT,
  TELCO_UNLOAD_POLICY_DEFERRED,
};

struct _TelcoLinuxInjectorState
{
  int telco_ctrlfd;
  int agent_ctrlfd;
};

union _TelcoControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

static void * telco_main (void * user_data);

static int telco_connect (const char * address, const TelcoLibcApi * libc);
static bool telco_send_hello (int sockfd, pid_t thread_id, const TelcoLibcApi * libc);
static bool telco_send_ready (int sockfd, const TelcoLibcApi * libc);
static bool telco_receive_ack (int sockfd, const TelcoLibcApi * libc);
static bool telco_send_bye (int sockfd, TelcoUnloadPolicy unload_policy, const TelcoLibcApi * libc);
static bool telco_send_error (int sockfd, TelcoMessageType type, const char * message, const TelcoLibcApi * libc);

static bool telco_receive_chunk (int sockfd, void * buffer, size_t length, const TelcoLibcApi * api);
static int telco_receive_fd (int sockfd, const TelcoLibcApi * libc);
static bool telco_send_chunk (int sockfd, const void * buffer, size_t length, const TelcoLibcApi * libc);
static void telco_enable_close_on_exec (int fd, const TelcoLibcApi * libc);

static size_t telco_strlen (const char * str);

static pid_t telco_gettid (void);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
telco_load (TelcoLoaderContext * ctx)
{
  ctx->libc->pthread_create (&ctx->worker, NULL, telco_main, ctx);
}

static void *
telco_main (void * user_data)
{
  TelcoLoaderContext * ctx = user_data;
  const TelcoLibcApi * libc = ctx->libc;
  pid_t thread_id;
  TelcoUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;
  TelcoLinuxInjectorState injector_state;

  thread_id = telco_gettid ();
  unload_policy = TELCO_UNLOAD_POLICY_IMMEDIATE;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;

  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    libc->close (ctrlfd_for_peer);

  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!telco_send_hello (ctrlfd, thread_id, libc))
    {
      libc->close (ctrlfd);
      ctrlfd = -1;
    }
  }
  if (ctrlfd == -1)
  {
    ctrlfd = telco_connect (ctx->fallback_address, libc);
    if (ctrlfd == -1)
      goto beach;

    if (!telco_send_hello (ctrlfd, thread_id, libc))
      goto beach;
  }

  if (ctx->agent_handle == NULL)
  {
    char agent_path[32];
    const void * pretend_caller_addr = libc->close;

    agent_codefd = telco_receive_fd (ctrlfd, libc);
    if (agent_codefd == -1)
      goto beach;

    libc->sprintf (agent_path, "/proc/self/fd/%d", agent_codefd);

    ctx->agent_handle = libc->dlopen (agent_path, libc->dlopen_flags, pretend_caller_addr);
    if (ctx->agent_handle == NULL)
      goto dlopen_failed;

    if (agent_codefd != -1)
    {
      libc->close (agent_codefd);
      agent_codefd = -1;
    }

    ctx->agent_entrypoint_impl = libc->dlsym (ctx->agent_handle, ctx->agent_entrypoint, pretend_caller_addr);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
  }

  agent_ctrlfd = telco_receive_fd (ctrlfd, libc);
  if (agent_ctrlfd != -1)
    telco_enable_close_on_exec (agent_ctrlfd, libc);

  if (!telco_send_ready (ctrlfd, libc))
    goto beach;
  if (!telco_receive_ack (ctrlfd, libc))
    goto beach;

  injector_state.telco_ctrlfd = ctrlfd;
  injector_state.agent_ctrlfd = agent_ctrlfd;

  ctx->agent_entrypoint_impl (ctx->agent_data, &unload_policy, &injector_state);

  ctrlfd = injector_state.telco_ctrlfd;
  agent_ctrlfd = injector_state.agent_ctrlfd;

  goto beach;

dlopen_failed:
  {
    telco_send_error (ctrlfd,
        TELCO_MESSAGE_ERROR_DLOPEN,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to load library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    telco_send_error (ctrlfd,
        TELCO_MESSAGE_ERROR_DLSYM,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (unload_policy == TELCO_UNLOAD_POLICY_IMMEDIATE && ctx->agent_handle != NULL)
      libc->dlclose (ctx->agent_handle);

    if (unload_policy != TELCO_UNLOAD_POLICY_DEFERRED)
      libc->pthread_detach (ctx->worker);

    if (agent_ctrlfd != -1)
      libc->close (agent_ctrlfd);

    if (agent_codefd != -1)
      libc->close (agent_codefd);

    if (ctrlfd != -1)
    {
      telco_send_bye (ctrlfd, unload_policy, libc);
      libc->close (ctrlfd);
    }

    return NULL;
  }
}

/* TODO: Handle EINTR. */

static int
telco_connect (const char * address, const TelcoLibcApi * libc)
{
  bool success = false;
  int sockfd;
  struct sockaddr_un addr;
  size_t len;
  const char * c;
  char ch;

  sockfd = libc->socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (libc->connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    libc->close (sockfd);
    sockfd = -1;
  }

  return sockfd;
}

static bool
telco_send_hello (int sockfd, pid_t thread_id, const TelcoLibcApi * libc)
{
  TelcoMessageType type = TELCO_MESSAGE_HELLO;
  TelcoHelloMessage hello = {
    .thread_id = thread_id,
  };

  if (!telco_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return telco_send_chunk (sockfd, &hello, sizeof (hello), libc);
}

static bool
telco_send_ready (int sockfd, const TelcoLibcApi * libc)
{
  TelcoMessageType type = TELCO_MESSAGE_READY;

  return telco_send_chunk (sockfd, &type, sizeof (type), libc);
}

static bool
telco_receive_ack (int sockfd, const TelcoLibcApi * libc)
{
  TelcoMessageType type;

  if (!telco_receive_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return type == TELCO_MESSAGE_ACK;
}

static bool
telco_send_bye (int sockfd, TelcoUnloadPolicy unload_policy, const TelcoLibcApi * libc)
{
  TelcoMessageType type = TELCO_MESSAGE_BYE;
  TelcoByeMessage bye = {
    .unload_policy = unload_policy,
  };

  if (!telco_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return telco_send_chunk (sockfd, &bye, sizeof (bye), libc);
}

static bool
telco_send_error (int sockfd, TelcoMessageType type, const char * message, const TelcoLibcApi * libc)
{
  uint16_t length;

  length = telco_strlen (message);

  #define TELCO_SEND_VALUE(v) \
      if (!telco_send_chunk (sockfd, &(v), sizeof (v), libc)) \
        return false
  #define TELCO_SEND_BYTES(data, size) \
      if (!telco_send_chunk (sockfd, data, size, libc)) \
        return false

  TELCO_SEND_VALUE (type);
  TELCO_SEND_VALUE (length);
  TELCO_SEND_BYTES (message, length);

  return true;
}

static bool
telco_receive_chunk (int sockfd, void * buffer, size_t length, const TelcoLibcApi * libc)
{
  void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    struct iovec io = {
      .iov_base = cursor,
      .iov_len = remaining
    };
    struct msghdr msg = {
      .msg_name = NULL,
      .msg_namelen = 0,
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = NULL,
      .msg_controllen = 0,
    };
    ssize_t n;

    n = libc->recvmsg (sockfd, &msg, 0);
    if (n <= 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static int
telco_receive_fd (int sockfd, const TelcoLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  TelcoControlMessage control;
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = &io,
    .msg_iovlen = 1,
    .msg_control = &control,
    .msg_controllen = sizeof (control),
  };

  res = libc->recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static bool
telco_send_chunk (int sockfd, const void * buffer, size_t length, const TelcoLibcApi * libc)
{
  const void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = libc->send (sockfd, cursor, remaining, MSG_NOSIGNAL);
    if (n == -1)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static void
telco_enable_close_on_exec (int fd, const TelcoLibcApi * libc)
{
  libc->fcntl (fd, F_SETFD, libc->fcntl (fd, F_GETFD) | FD_CLOEXEC);
}

static size_t
telco_strlen (const char * str)
{
  size_t n = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    asm ("");
    n++;
  }

  return n;
}

static pid_t
telco_gettid (void)
{
  return telco_syscall_0 (SYS_gettid);
}
