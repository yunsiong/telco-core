#ifndef __TELCO_INJECT_CONTEXT_H__
#define __TELCO_INJECT_CONTEXT_H__

#ifdef NOLIBC
typedef void * pthread_t;
typedef struct _pthread_attr_t pthread_attr_t;
struct msghdr;
struct sockaddr;
typedef unsigned int socklen_t;
#else
# include <dlfcn.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/socket.h>
#endif

typedef size_t TelcoBootstrapStatus;
typedef struct _TelcoBootstrapContext TelcoBootstrapContext;
typedef struct _TelcoLoaderContext TelcoLoaderContext;
typedef struct _TelcoLibcApi TelcoLibcApi;
typedef uint8_t TelcoMessageType;
typedef struct _TelcoHelloMessage TelcoHelloMessage;
typedef struct _TelcoByeMessage TelcoByeMessage;
typedef int TelcoRtldFlavor;

enum _TelcoBootstrapStatus
{
  TELCO_BOOTSTRAP_SUCCESS,
  TELCO_BOOTSTRAP_AUXV_NOT_FOUND,
  TELCO_BOOTSTRAP_TOO_EARLY,
  TELCO_BOOTSTRAP_LIBC_LOAD_ERROR,
  TELCO_BOOTSTRAP_LIBC_UNSUPPORTED,
  TELCO_BOOTSTRAP_MMAP_ERROR,
};

struct _TelcoBootstrapContext
{
  size_t page_size;
  const char * fallback_ld;
  const char * fallback_libc;
  TelcoRtldFlavor rtld_flavor;
  void * rtld_base;
  void * r_brk;
  size_t loader_size;
  void * loader_base;
  int enable_ctrlfds;
  int ctrlfds[2];
  TelcoLibcApi * libc;
};

struct _TelcoLoaderContext
{
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  TelcoLibcApi * libc;

  pthread_t worker;
  void * agent_handle;
  void (* agent_entrypoint_impl) (const char * data, int * unload_policy, void * injector_state);
};

struct _TelcoLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
  int (* socket) (int domain, int type, int protocol);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  int (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* fcntl) (int fd, int cmd, ...);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags, const void * caller_addr);
  int dlopen_flags;
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol, const void * caller_addr);
  char * (* dlerror) (void);
};

enum _TelcoMessageType
{
  TELCO_MESSAGE_HELLO,
  TELCO_MESSAGE_READY,
  TELCO_MESSAGE_ACK,
  TELCO_MESSAGE_BYE,
  TELCO_MESSAGE_ERROR_DLOPEN,
  TELCO_MESSAGE_ERROR_DLSYM,
};

struct _TelcoHelloMessage
{
  pid_t thread_id;
};

struct _TelcoByeMessage
{
  int unload_policy;
};

enum _TelcoRtldFlavor
{
  TELCO_RTLD_UNKNOWN,
  TELCO_RTLD_NONE,
  TELCO_RTLD_GLIBC,
  TELCO_RTLD_UCLIBC,
  TELCO_RTLD_MUSL,
  TELCO_RTLD_ANDROID,
};

#endif
