#include "telco-helper-backend.h"

#include "telco-tvos.h"

#include <capstone.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#import <Foundation/Foundation.h>
#include <glib-unix.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumarmwriter.h>
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <util.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
# define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

#ifndef PROC_PIDPATHINFO_MAXSIZE
# define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
#endif

#define TELCO_PSR_THUMB                  0x20
#define TELCO_MAX_BREAKPOINTS            4
#define TELCO_MAX_PAGE_POOL              8

#if (defined (HAVE_ARM) || defined (HAVE_ARM64)) && !defined (__darwin_arm_thread_state64_get_pc)
# define __darwin_arm_thread_state64_get_pc(ts) \
    ((ts).__pc)
# define __darwin_arm_thread_state64_get_pc_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__pc))
# define __darwin_arm_thread_state64_set_pc_fptr(ts, fptr) \
    ((ts).__pc = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_lr(ts) \
    ((ts).__lr)
# define __darwin_arm_thread_state64_get_lr_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__lr))
# define __darwin_arm_thread_state64_set_lr_fptr(ts, fptr) \
    ((ts).__lr = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_sp(ts) \
    ((ts).__sp)
# define __darwin_arm_thread_state64_set_sp(ts, ptr) \
    ((ts).__sp = (uintptr_t) (ptr))
# define __darwin_arm_thread_state64_get_fp(ts) \
    ((ts).__fp)
# define __darwin_arm_thread_state64_set_fp(ts, ptr) \
    ((ts).__fp = (uintptr_t) (ptr))
#endif

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto mach_failure; \
  }
#define CHECK_BSD_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto bsd_failure; \
  }

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
# define CORE_FOUNDATION "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
#else
# define CORE_FOUNDATION "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
#endif

typedef struct _TelcoHelperContext TelcoHelperContext;
typedef struct _TelcoSpawnInstance TelcoSpawnInstance;
typedef guint TelcoDyldFlavor;
typedef struct _TelcoSpawnInstanceDyldData TelcoSpawnInstanceDyldData;
typedef guint TelcoBreakpointPhase;
typedef guint TelcoBreakpointRepeat;
typedef struct _TelcoBreakpoint TelcoBreakpoint;
typedef guint TelcoRetState;
typedef struct _TelcoPagePoolEntry TelcoPagePoolEntry;
typedef struct _TelcoInjectInstance TelcoInjectInstance;
typedef struct _TelcoInjectPayloadLayout TelcoInjectPayloadLayout;
typedef struct _TelcoAgentDetails TelcoAgentDetails;
typedef struct _TelcoAgentContext TelcoAgentContext;
typedef struct _TelcoAgentEmitContext TelcoAgentEmitContext;

typedef struct _TelcoExceptionPortSet TelcoExceptionPortSet;
typedef union _TelcoDebugState TelcoDebugState;
typedef int TelcoConvertThreadStateDirection;
typedef guint TelcoAslr;

struct _TelcoHelperContext
{
  dispatch_queue_t dispatch_queue;
};

struct _TelcoExceptionPortSet
{
  mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
};

union _TelcoDebugState
{
#ifdef HAVE_I386
  x86_debug_state_t state;
#else
  arm_debug_state32_t s32;
  arm_debug_state64_t s64;
#endif
};

enum _TelcoBreakpointRepeat
{
  TELCO_BREAKPOINT_REPEAT_NEVER,
  TELCO_BREAKPOINT_REPEAT_ONCE,
  TELCO_BREAKPOINT_REPEAT_ALWAYS
};

struct _TelcoBreakpoint
{
  GumAddress address;
  TelcoBreakpointRepeat repeat;
  guint32 original;
};

struct _TelcoPagePoolEntry
{
  GumAddress page_start;
  GumAddress scratch_page;
};

struct _TelcoSpawnInstance
{
  TelcoDarwinHelperBackend * backend;
  guint pid;
  GumCpuType cpu_type;
  mach_port_t thread;
  TelcoDebugState previous_debug_state;
  TelcoDebugState breakpoint_debug_state;

  mach_port_t server_port;
  dispatch_source_t server_recv_source;
  TelcoExceptionPortSet previous_ports;

  __Request__exception_raise_state_identity_t pending_request;

  GumDarwinModule * dyld;
  size_t dyld_size;
  TelcoDyldFlavor dyld_flavor;

  TelcoBreakpointPhase breakpoint_phase;
  TelcoBreakpoint breakpoints[TELCO_MAX_BREAKPOINTS];
  TelcoPagePoolEntry page_pool[TELCO_MAX_PAGE_POOL];
  gint single_stepping;

  mach_vm_address_t lib_name;
  mach_vm_address_t bootstrapper_name;
  mach_vm_address_t fake_helpers;
  mach_vm_address_t fake_error_buf;
  mach_vm_address_t dyld_data;

  GumAddress modern_entry_address;

  /* V4+ */
  GumAddress info_ptr_address;

  /* V3- */
  GumAddress dlopen_address;
  GumAddress cf_initialize_address;
  GumAddress info_address;
  GumAddress register_helpers_address;
  GumAddress dlerror_clear_address;
  GumAddress helpers_ptr_address;
  GumAddress ret_gadget;
  TelcoRetState ret_state;
  GHashTable * do_modinit_strcmp_checks;

  mach_port_t task;
  GumDarwinUnifiedThreadState previous_thread_state;
};

enum _TelcoDyldFlavor
{
  TELCO_DYLD_V4_PLUS,
  TELCO_DYLD_V3_MINUS,
};

enum _TelcoBreakpointPhase
{
  TELCO_BREAKPOINT_DETECT_FLAVOR,

  /* V4+ */
  TELCO_BREAKPOINT_SET_LIBDYLD_INITIALIZE_CALLER_BREAKPOINT,
  TELCO_BREAKPOINT_LIBSYSTEM_INITIALIZED,

  /* V3- */
  TELCO_BREAKPOINT_SET_HELPERS,
  TELCO_BREAKPOINT_DLOPEN_LIBC,
  TELCO_BREAKPOINT_SKIP_CLEAR,
  TELCO_BREAKPOINT_DLOPEN_BOOTSTRAPPER,

  /* Common */
  TELCO_BREAKPOINT_CF_INITIALIZE,
  TELCO_BREAKPOINT_CLEANUP,
  TELCO_BREAKPOINT_DONE
};

enum _TelcoRetState
{
  TELCO_RET_FROM_HELPER,
};

struct _TelcoSpawnInstanceDyldData
{
  gchar libc[32];
  guint8 helpers[32];
  gchar bootstrapper[64];
  guint8 error_buf[1024];
};

struct _TelcoInjectInstance
{
  guint id;

  guint pid;
  mach_port_t task;

  mach_vm_address_t payload_address;
  mach_vm_size_t payload_size;
  TelcoAgentContext * agent_context;
  mach_vm_address_t remote_agent_context;
  mach_vm_size_t agent_context_size;
  gboolean is_loaded;
  gboolean is_mapped;

  mach_port_t thread;
  dispatch_source_t thread_monitor_source;
#ifdef HAVE_I386
  x86_thread_state_t thread_state;
#else
  arm_thread_state_t thread_state32;
  arm_unified_thread_state_t thread_state64;
#endif
  thread_state_t thread_state_data;
  mach_msg_type_number_t thread_state_count;
  thread_state_flavor_t thread_state_flavor;

  TelcoDarwinHelperBackend * backend;
};

struct _TelcoInjectPayloadLayout
{
  guint stack_guard_size;
  guint stack_size;

  guint code_offset;
  guint mach_code_offset;
  guint pthread_code_offset;
  guint data_offset;
  guint data_size;
  guint stack_guard_offset;
  guint stack_bottom_offset;
  guint stack_top_offset;
};

struct _TelcoAgentDetails
{
  guint pid;
  const gchar * dylib_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;
  GumCpuType cpu_type;
};

struct _TelcoAgentContext
{
  /* State */
  TelcoUnloadPolicy unload_policy;
  mach_port_t task;
  mach_port_t mach_thread;
  mach_port_t posix_thread;
  uint64_t posix_tid;
  gboolean constructed;
  gpointer module_handle;

  /* Mach thread */
  GumAddress mach_task_self_impl;
  GumAddress mach_thread_self_impl;

  GumAddress mach_port_allocate_impl;
  mach_port_right_t mach_port_allocate_right;
  mach_port_t receive_port;

  GumAddress pthread_create_impl;
  GumAddress pthread_create_from_mach_thread_impl;
  GumAddress pthread_create_start_routine;
  GumAddress pthread_create_arg;

  GumAddress mach_msg_receive_impl;
  GumAddress message_that_never_arrives;

  /* POSIX thread */
  GumAddress pthread_threadid_np_impl;

  GumAddress dlopen_impl;
  GumAddress dylib_path;
  int dlopen_mode;

  GumAddress dlsym_impl;
  GumAddress entrypoint_name;

  GumAddress entrypoint_data;
  GumAddress mapped_range;

  GumAddress dlclose_impl;

  GumAddress pthread_detach_impl;
  GumAddress pthread_self_impl;

  GumAddress mach_port_destroy_impl;

  GumAddress thread_terminate_impl;

  /* Storage -- at the end to make the above field offsets smaller */
  mach_msg_empty_rcv_t message_that_never_arrives_storage;
  gchar dylib_path_storage[256];
  gchar entrypoint_name_storage[256];
  gchar entrypoint_data_storage[4096];
  GumMemoryRange mapped_range_storage;
};

struct _TelcoAgentEmitContext
{
  guint8 * code;
#ifdef HAVE_I386
  GumX86Writer cw;
#else
  GumThumbWriter tw;
  GumArm64Writer aw;
#endif
  GumDarwinMapper * mapper;
};

enum _TelcoConvertThreadStateDirection
{
  TELCO_CONVERT_THREAD_STATE_IN = 1,
  TELCO_CONVERT_THREAD_STATE_OUT
};

enum _TelcoAslr
{
  TELCO_ASLR_AUTO,
  TELCO_ASLR_DISABLE
};

static TelcoSpawnInstance * telco_spawn_instance_new (TelcoDarwinHelperBackend * backend);
static void telco_spawn_instance_free (TelcoSpawnInstance * instance);
static void telco_spawn_instance_resume (TelcoSpawnInstance * self);

static void telco_spawn_instance_on_server_recv (void * context);
static gboolean telco_spawn_instance_handle_breakpoint (TelcoSpawnInstance * self, TelcoBreakpoint * breakpoint, GumDarwinUnifiedThreadState * state);
static gboolean telco_spawn_instance_handle_dyld_restart (TelcoSpawnInstance * self);
static gboolean telco_spawn_instance_handle_modinit (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, GumAddress pc);
static void telco_spawn_instance_receive_breakpoint_request (TelcoSpawnInstance * self);
static void telco_spawn_instance_send_breakpoint_response (TelcoSpawnInstance * self);
static gboolean telco_spawn_instance_is_libc_initialized (TelcoSpawnInstance * self);
static void telco_spawn_instance_set_libc_initialized (TelcoSpawnInstance * self);
static kern_return_t telco_spawn_instance_create_dyld_data (TelcoSpawnInstance * self);
static void telco_spawn_instance_destroy_dyld_data (TelcoSpawnInstance * self);
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
static gboolean telco_pick_ios_tvos_bootstrapper (const GumModuleDetails * details, gpointer user_data);
#endif
static void telco_spawn_instance_unset_helpers (TelcoSpawnInstance * self);
static void telco_spawn_instance_call_set_helpers (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, mach_vm_address_t helpers);
static void telco_spawn_instance_call_dlopen (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, mach_vm_address_t lib_name, int mode);
static gboolean telco_find_cf_initialize (const GumModuleDetails * details, gpointer user_data);
static void telco_spawn_instance_call_cf_initialize (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state);
static void telco_spawn_instance_set_nth_breakpoint (TelcoSpawnInstance * self, guint n, GumAddress break_at, TelcoBreakpointRepeat repeat);
static void telco_spawn_instance_enable_nth_breakpoint (TelcoSpawnInstance * self, guint n);
static void telco_spawn_instance_unset_nth_breakpoint (TelcoSpawnInstance * self, guint n);
static void telco_spawn_instance_disable_nth_breakpoint (TelcoSpawnInstance * self, guint n);
static guint32 telco_spawn_instance_put_software_breakpoint (TelcoSpawnInstance * self, GumAddress where, guint index);
static guint32 telco_spawn_instance_overwrite_arm64_instruction (TelcoSpawnInstance * self, GumAddress address, guint32 new_instruction);

static void telco_make_pty (int fds[2]);
static void telco_configure_terminal_attributes (gint fd);

static TelcoInjectInstance * telco_inject_instance_new (TelcoDarwinHelperBackend * backend, guint id, guint pid);
static TelcoInjectInstance * telco_inject_instance_clone (const TelcoInjectInstance * instance, guint id);
static void telco_inject_instance_free (TelcoInjectInstance * instance);
static gboolean telco_inject_instance_task_did_not_exec (TelcoInjectInstance * instance);

static gboolean telco_inject_instance_start_thread (TelcoInjectInstance * self, GError ** error);
static void telco_inject_instance_on_mach_thread_dead (void * context);
static void telco_inject_instance_join_posix_thread (TelcoInjectInstance * self, mach_port_t posix_thread);
static void telco_inject_instance_on_posix_thread_dead (void * context);

static gboolean telco_agent_context_init (TelcoAgentContext * self, const TelcoAgentDetails * details, const TelcoInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error);
static gboolean telco_agent_context_init_functions (TelcoAgentContext * self, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper,
    GError ** error);

static void telco_agent_context_emit_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);
static void telco_agent_context_emit_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);

static mach_port_t telco_obtain_thread_port_for_thread_id (mach_port_t task, uint64_t thread_id);
static kern_return_t telco_get_thread_state (mach_port_t thread, thread_state_flavor_t flavor, gpointer state,
    mach_msg_type_number_t * count);
static kern_return_t telco_set_thread_state (mach_port_t thread, thread_state_flavor_t flavor, gconstpointer state,
    mach_msg_type_number_t count);
static kern_return_t telco_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type);
static kern_return_t telco_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type);
static kern_return_t telco_convert_thread_state_inplace (mach_port_t thread, TelcoConvertThreadStateDirection direction,
    thread_state_flavor_t flavor, gpointer state, mach_msg_type_number_t * count);
static kern_return_t telco_convert_thread_state (mach_port_t thread, TelcoConvertThreadStateDirection direction,
    thread_state_flavor_t flavor, gconstpointer in_state, mach_msg_type_number_t in_state_count,
    gpointer out_state, mach_msg_type_number_t * out_state_count);
static void telco_set_nth_hardware_breakpoint (gpointer state, guint n, GumAddress break_at, GumCpuType cpu_type);
static void telco_set_hardware_single_step (gpointer debug_state, GumDarwinUnifiedThreadState * thread_state, gboolean enabled, GumCpuType cpu_type);
static gboolean telco_is_hardware_breakpoint_support_working (void);

static GumAddress telco_find_run_initializers_call (mach_port_t task, GumCpuType cpu_type, GumAddress start);
static GHashTable * telco_find_modinit_strcmp_checks (mach_port_t task, GumDarwinModule * dyld);
static GumAddress telco_find_function_end (mach_port_t task, GumCpuType cpu_type, GumAddress start, gsize max_size);
static csh telco_create_capstone (GumCpuType cpu_type, GumAddress start);

static gboolean telco_parse_aslr_option (GVariant * value, TelcoAslr * aslr, GError ** error);

static void telco_mapper_library_blob_deallocate (TelcoMappedLibraryBlob * self);

extern int fileport_makeport (int fd, mach_port_t * port);
extern int proc_pidpath (int pid, void * buffer, uint32_t buffer_size);

void
telco_darwin_helper_backend_make_pipe_endpoints (guint local_task, guint remote_pid, guint remote_task, TelcoPipeEndpoints * result, GError ** error)
{
  mach_port_t self_task;
  int status, sockets[2] = { -1, -1 }, i;
  mach_port_t local_wrapper = MACH_PORT_NULL;
  mach_port_t remote_wrapper = MACH_PORT_NULL;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  mach_msg_type_name_t acquired_type;
  mach_msg_header_t init;
  gchar * local_address, * remote_address;
  kern_return_t kr;
  const gchar * failed_operation;

  self_task = mach_task_self ();

  if (local_task == MACH_PORT_NULL)
    local_task = self_task;

  status = socketpair (AF_UNIX, SOCK_STREAM, 0, sockets);
  CHECK_BSD_RESULT (status, ==, 0, "socketpair");

  for (i = 0; i != G_N_ELEMENTS (sockets); i++)
  {
    int fd = sockets[i];
    const int no_sigpipe = TRUE;

    fcntl (fd, F_SETFD, FD_CLOEXEC);
    setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof (no_sigpipe));
    telco_unix_socket_tune_buffer_sizes (fd);
  }

  status = fileport_makeport (sockets[0], &local_wrapper);
  CHECK_BSD_RESULT (status, ==, 0, "fileport_makeport local");

  status = fileport_makeport (sockets[1], &remote_wrapper);
  CHECK_BSD_RESULT (status, ==, 0, "fileport_makeport remote");

  kr = mach_port_allocate (local_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate local_rx");

  kr = mach_port_allocate (remote_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate remote_rx");

  kr = mach_port_extract_right (local_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &local_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right local_rx");

  kr = mach_port_extract_right (remote_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &remote_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right remote_rx");

  init.msgh_size = sizeof (init);
  init.msgh_reserved = 0;
  init.msgh_id = 3;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = local_tx;
  init.msgh_local_port = local_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send local_tx");
  local_tx = MACH_PORT_NULL;
  local_wrapper = MACH_PORT_NULL;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = remote_tx;
  init.msgh_local_port = remote_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send remote_tx");
  remote_tx = MACH_PORT_NULL;
  remote_wrapper = MACH_PORT_NULL;

  local_address = g_strdup_printf ("pipe:port=0x%x", local_rx);
  remote_address = g_strdup_printf ("pipe:port=0x%x", remote_rx);
  local_rx = MACH_PORT_NULL;
  remote_rx = MACH_PORT_NULL;
  telco_pipe_endpoints_init (result, local_address, remote_address);
  g_free (remote_address);
  g_free (local_address);

  goto beach;

mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
        remote_pid, failed_operation, mach_error_string (kr));
    goto beach;
  }
bsd_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
        remote_pid, failed_operation, g_strerror (errno));
    goto beach;
  }
beach:
  {
    guint i;

    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_tx);

    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (remote_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (local_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    if (remote_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_wrapper);
    if (local_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_wrapper);

    for (i = 0; i != G_N_ELEMENTS (sockets); i++)
    {
      int fd = sockets[i];
      if (fd != -1)
        close (fd);
    }

    return;
  }
}

void
telco_darwin_helper_backend_make_pipe_endpoint_from_socket (guint pid, guint task, GSocket * sock, gchar ** address, GError ** error)
{
  mach_port_t self_task;
  int status;
  mach_port_t wrapper = MACH_PORT_NULL;
  mach_port_t rx = MACH_PORT_NULL;
  mach_port_t tx = MACH_PORT_NULL;
  mach_msg_type_name_t acquired_type;
  mach_msg_header_t init;
  kern_return_t kr;
  const gchar * failed_operation;

  self_task = mach_task_self ();

  status = fileport_makeport (g_socket_get_fd (sock), &wrapper);
  CHECK_BSD_RESULT (status, ==, 0, "fileport_makeport");

  kr = mach_port_allocate (task, MACH_PORT_RIGHT_RECEIVE, &rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate");

  kr = mach_port_extract_right (task, rx, MACH_MSG_TYPE_MAKE_SEND, &tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right");

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_size = sizeof (init);
  init.msgh_remote_port = tx;
  init.msgh_local_port = wrapper;
  init.msgh_reserved = 0;
  init.msgh_id = 3;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send");
  tx = MACH_PORT_NULL;
  wrapper = MACH_PORT_NULL;

  *address = g_strdup_printf ("pipe:port=0x%x", rx);
  rx = MACH_PORT_NULL;

  goto beach;

mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoint from socket for process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (kr));
    goto beach;
  }
bsd_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoint from socket for process with pid %u (%s returned '%s')",
        pid, failed_operation, g_strerror (errno));
    goto beach;
  }
beach:
  {
    if (tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, tx);

    if (rx != MACH_PORT_NULL)
      mach_port_mod_refs (task, rx, MACH_PORT_RIGHT_RECEIVE, -1);

    if (wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, wrapper);

    return;
  }
}

guint
telco_darwin_helper_backend_task_for_pid (guint pid, GError ** error)
{
  gboolean remote_pid_exists;
  mach_port_t task;
  kern_return_t kr;

  remote_pid_exists = kill (pid, 0) == 0 || errno == EPERM;
  if (!remote_pid_exists)
    goto invalid_pid;

  kr = task_for_pid (mach_task_self (), pid, &task);
  if (kr != KERN_SUCCESS)
    goto permission_denied;

  return task;

invalid_pid:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_PROCESS_NOT_FOUND,
        "Unable to find process with pid %u",
        pid);
    return 0;
  }
permission_denied:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u from the current user account",
        pid);
    return 0;
  }
}

void
telco_darwin_helper_backend_deallocate_port (guint port)
{
  mach_port_deallocate (mach_task_self (), port);
}

gboolean
telco_darwin_helper_backend_is_mmap_available (void)
{
#ifdef HAVE_MAPPER
  return TRUE;
#else
  return FALSE;
#endif
}

void
telco_darwin_helper_backend_mmap (guint task, GBytes * blob, TelcoMappedLibraryBlob * result, GError ** error)
{
  gconstpointer data;
  gsize size, aligned_size, page_size;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;
  kern_return_t kr;

  if (task == MACH_PORT_NULL)
    task = mach_task_self ();

  data = g_bytes_get_data (blob, &size);

  mapped_address = 0;
  page_size = getpagesize ();
  aligned_size = (size + page_size - 1) & ~(page_size - 1);

  kr = mach_vm_remap (task, &mapped_address, aligned_size, 0, VM_FLAGS_ANYWHERE,
      mach_task_self (), GPOINTER_TO_SIZE (data), TRUE, &cur_protection, &max_protection,
      VM_INHERIT_COPY);
  if (kr != KERN_SUCCESS)
    goto permission_denied;

  kr = mach_vm_protect (task, mapped_address, aligned_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr != KERN_SUCCESS)
  {
    mach_vm_deallocate (task, mapped_address, aligned_size);
    goto permission_denied;
  }

  telco_mapped_library_blob_init (result, mapped_address, size, aligned_size);

  return;

permission_denied:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_PERMISSION_DENIED,
        "Unable to mmap (%s)",
        mach_error_string (kr));
  }
}

void
_telco_darwin_helper_backend_create_context (TelcoDarwinHelperBackend * self)
{
  TelcoHelperContext * ctx;

  ctx = g_slice_new (TelcoHelperContext);
  ctx->dispatch_queue = dispatch_queue_create ("re.telco.helper.queue", DISPATCH_QUEUE_SERIAL);

  self->context = ctx;
}

void
_telco_darwin_helper_backend_destroy_context (TelcoDarwinHelperBackend * self)
{
  TelcoHelperContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (TelcoHelperContext, ctx);
}

void
_telco_darwin_helper_backend_schedule_on_dispatch_queue (TelcoDarwinHelperBackend * self, TelcoDarwinHelperBackendDispatchWorker worker, gpointer user_data)
{
  TelcoHelperContext * ctx = self->context;

  dispatch_async (ctx->dispatch_queue, ^
  {
    worker (user_data);
  });
}

guint
_telco_darwin_helper_backend_spawn (TelcoDarwinHelperBackend * self, const gchar * path,
    TelcoHostSpawnOptions * options, TelcoStdioPipes ** pipes, GError ** error)
{
  pid_t pid;
  TelcoSpawnInstance * instance;
  gchar ** argv, ** envp;
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attributes;
  sigset_t signal_mask_set;
  short flags;
  int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
  TelcoAslr aslr = TELCO_ASLR_AUTO;
  GVariant * aslr_value;
  gchar * old_cwd = NULL;
  int result, spawn_errno;

  instance = telco_spawn_instance_new (self);

  argv = telco_host_spawn_options_compute_argv (options, path, NULL);
  envp = telco_host_spawn_options_compute_envp (options, NULL);

  posix_spawn_file_actions_init (&file_actions);

  posix_spawnattr_init (&attributes);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attributes, &signal_mask_set);

  flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED;

  switch (options->stdio)
  {
    case TELCO_STDIO_INHERIT:
      *pipes = NULL;

      posix_spawn_file_actions_adddup2 (&file_actions, 0, 0);
      posix_spawn_file_actions_adddup2 (&file_actions, 1, 1);
      posix_spawn_file_actions_adddup2 (&file_actions, 2, 2);

      break;

    case TELCO_STDIO_PIPE:
      telco_make_pty (stdin_pipe);
      telco_make_pty (stdout_pipe);
      telco_make_pty (stderr_pipe);

      *pipes = telco_stdio_pipes_new (stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);

      posix_spawn_file_actions_adddup2 (&file_actions, stdin_pipe[0], 0);
      posix_spawn_file_actions_adddup2 (&file_actions, stdout_pipe[1], 1);
      posix_spawn_file_actions_adddup2 (&file_actions, stderr_pipe[1], 2);

      break;

    default:
      g_assert_not_reached ();
  }

  aslr_value = g_hash_table_lookup (options->aux, "aslr");
  if (aslr_value != NULL && !telco_parse_aslr_option (aslr_value, &aslr, error))
    goto early_failure;
  if (aslr == TELCO_ASLR_DISABLE)
    flags |= _POSIX_SPAWN_DISABLE_ASLR;

  posix_spawnattr_setflags (&attributes, flags);

  if (strlen (options->cwd) > 0)
  {
    old_cwd = g_get_current_dir ();
    if (chdir (options->cwd) != 0)
      goto chdir_failed;
  }

  result = posix_spawn (&pid, path, &file_actions, &attributes, argv, envp);
  spawn_errno = errno;

  if (old_cwd != NULL)
    chdir (old_cwd);

  if (options->stdio == TELCO_STDIO_PIPE)
  {
    close (stdin_pipe[0]);
    close (stdout_pipe[1]);
    close (stderr_pipe[1]);
  }

  posix_spawnattr_destroy (&attributes);

  posix_spawn_file_actions_destroy (&file_actions);

  if (result != 0)
    goto spawn_failed;

  instance->pid = pid;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instances), GUINT_TO_POINTER (pid), instance);

  goto beach;

chdir_failed:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_INVALID_ARGUMENT,
        "Unable to change directory to '%s'",
        options->cwd);

    goto early_failure;
  }
spawn_failed:
  {
    if (spawn_errno == EAGAIN)
    {
      g_set_error (error,
          TELCO_ERROR,
          TELCO_ERROR_EXECUTABLE_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': unsupported file format",
          path);
    }
    else
    {
      g_set_error (error,
          TELCO_ERROR,
          TELCO_ERROR_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': %s",
          path, g_strerror (spawn_errno));
    }

    goto any_failure;
  }
early_failure:
  {
    posix_spawnattr_destroy (&attributes);
    posix_spawn_file_actions_destroy (&file_actions);

    goto any_failure;
  }
any_failure:
  {
    if (instance->pid != 0)
      kill (instance->pid, SIGKILL);
    telco_spawn_instance_free (instance);

    pid = 0;

    goto beach;
  }
beach:
  {
    g_free (old_cwd);
    g_strfreev (envp);
    g_strfreev (argv);

    return pid;
  }
}

gchar *
telco_darwin_helper_backend_path_for_pid (guint pid, GError ** error)
{
  gchar path[PROC_PIDPATHINFO_MAXSIZE];

  if (proc_pidpath (pid, path, sizeof (path)) <= 0)
    goto invalid_pid;

  return g_strdup (path);

invalid_pid:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_INVALID_ARGUMENT,
        "%s",
        g_strerror (errno));
    return NULL;
  }
}

#if defined (HAVE_IOS) || defined (HAVE_TVOS)

#import "springboard.h"

static void telco_darwin_helper_backend_launch_using_fbs (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target);
static void telco_darwin_helper_backend_launch_using_sbs (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target);
#ifdef HAVE_TVOS
static void telco_darwin_helper_backend_launch_using_lsaw (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target);
#endif

static guint telco_kill_application (NSString * identifier);
static gboolean telco_has_active_prewarm (gint pid);
static guint8 * telco_skip_string (guint8 * cursor, guint8 * end);

static NSArray * telco_argv_to_arguments_array (gchar * const * argv, gint argv_length);
static NSDictionary * telco_envp_to_environment_dictionary (gchar * const * envp, gint envp_length);

static gboolean telco_find_uikit (const GumDependencyDetails * details, gboolean * has_uikit);

void
_telco_darwin_helper_backend_launch (const gchar * identifier, TelcoHostSpawnOptions * options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  NSAutoreleasePool * pool;
  NSString * identifier_value;
  GVariant * url;
  NSURL * url_value = nil;
  GError * error = NULL;

  pool = [[NSAutoreleasePool alloc] init];

  identifier_value = [NSString stringWithUTF8String:identifier];

  url = g_hash_table_lookup (options->aux, "url");
  if (url != NULL)
  {
    if (!g_variant_is_of_type (url, G_VARIANT_TYPE_STRING))
      goto invalid_url;
    url_value = [NSURL URLWithString:[NSString stringWithUTF8String:g_variant_get_string (url, NULL)]];
  }

#ifdef HAVE_TVOS
  telco_darwin_helper_backend_launch_using_lsaw (identifier_value, url_value, options, on_complete, on_complete_target);
  goto beach;
#endif

  if (_telco_get_springboard_api ()->fbs != NULL)
  {
    telco_darwin_helper_backend_launch_using_fbs (identifier_value, url_value, options, on_complete, on_complete_target);
  }
  else
  {
    telco_darwin_helper_backend_launch_using_sbs (identifier_value, url_value, options, on_complete, on_complete_target);
  }

  goto beach;

invalid_url:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_INVALID_ARGUMENT,
        "The 'url' option must be a string");
    goto failure;
  }
failure:
  {
    on_complete (NULL, error, on_complete_target);
    goto beach;
  }
beach:
  {
    [pool release];
  }
}

static void
telco_darwin_helper_backend_launch_using_fbs (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  TelcoSpringboardApi * api;
  NSMutableDictionary * debug_options, * open_options;
  TelcoStdioPipes * pipes = NULL;
  GError * error = NULL;
  TelcoAslr aslr = TELCO_ASLR_AUTO;
  GVariant * aslr_value;
  FBSSystemService * service;
  mach_port_t client_port;
  FBSOpenResultCallback result_callback;

  api = _telco_get_springboard_api ();

  debug_options = [NSMutableDictionary dictionary];

  open_options = [NSMutableDictionary dictionary];
  [open_options setObject:@YES
                   forKey:api->FBSOpenApplicationOptionKeyUnlockDevice];
  [open_options setObject:debug_options
                   forKey:api->FBSOpenApplicationOptionKeyDebuggingOptions];

  if (spawn_options->has_argv)
  {
    [debug_options setObject:telco_argv_to_arguments_array (spawn_options->argv, spawn_options->argv_length1)
                      forKey:api->FBSDebugOptionKeyArguments];
  }

  if (spawn_options->has_envp)
    goto envp_not_supported;

  if (spawn_options->has_env)
  {
    [debug_options setObject:telco_envp_to_environment_dictionary (spawn_options->env, spawn_options->env_length1)
                      forKey:api->FBSDebugOptionKeyEnvironment];
  }

  if (strlen (spawn_options->cwd) > 0)
    goto cwd_not_supported;

  if (spawn_options->stdio == TELCO_STDIO_PIPE)
  {
    gint stdout_master, stdout_slave, stderr_master, stderr_slave;
    gchar stdout_name[PATH_MAX], stderr_name[PATH_MAX];

    openpty (&stdout_master, &stdout_slave, stdout_name, NULL, NULL);
    openpty (&stderr_master, &stderr_slave, stderr_name, NULL, NULL);

    pipes = telco_stdio_pipes_new (-1, stdout_master, stderr_master);

    telco_configure_terminal_attributes (stdout_master);
    telco_configure_terminal_attributes (stderr_master);

    telco_stdio_pipes_retain (pipes, stdout_slave);
    telco_stdio_pipes_retain (pipes, stderr_slave);

    chmod (stdout_name, 0666);
    chmod (stderr_name, 0666);

    [debug_options setObject:[NSString stringWithUTF8String:stdout_name]
                      forKey:api->FBSDebugOptionKeyStandardOutPath];
    [debug_options setObject:[NSString stringWithUTF8String:stderr_name]
                      forKey:api->FBSDebugOptionKeyStandardErrorPath];
  }

  aslr_value = g_hash_table_lookup (spawn_options->aux, "aslr");
  if (aslr_value != NULL && !telco_parse_aslr_option (aslr_value, &aslr, &error))
    goto failure;
  if (aslr == TELCO_ASLR_DISABLE)
  {
    [debug_options setObject:@YES
                      forKey:api->FBSDebugOptionKeyDisableASLR];
  }

  service = [api->FBSSystemService sharedService];

  client_port = [service createClientPort];

  result_callback = ^(NSError * error)
  {
    TelcoStdioPipes * pending_pipes = pipes;
    GError * pending_error = NULL;

    if (error == nil)
    {
      [service cleanupClientPort:client_port];
    }
    else
    {
      g_clear_object (&pending_pipes);

      pending_error = g_error_new (
          TELCO_ERROR,
          TELCO_ERROR_NOT_SUPPORTED,
          "Unable to launch iOS app via FBS: %s",
          [[error localizedDescription] UTF8String]);
    }

    on_complete (pending_pipes, pending_error, on_complete_target);
  };

  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^
  {
    telco_kill_application (identifier);

    if (url != nil)
    {
      [service openURL:url
           application:identifier
               options:open_options
            clientPort:client_port
            withResult:result_callback];
    }
    else
    {
      [service openApplication:identifier
                       options:open_options
                    clientPort:client_port
                    withResult:result_callback];
    }
  });

  return;

envp_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'envp' option is not supported when spawning iOS apps, use the 'env' option instead");
    goto failure;
  }
cwd_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'cwd' option is not supported when spawning iOS apps");
    goto failure;
  }
failure:
  {
    on_complete (NULL, error, on_complete_target);
    return;
  }
}

static void
telco_darwin_helper_backend_launch_using_sbs (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  TelcoSpringboardApi * api;
  NSDictionary * params, * launch_options;
  GError * error = NULL;
  TelcoAslr aslr = TELCO_ASLR_AUTO;
  GVariant * aslr_value;

  api = _telco_get_springboard_api ();

  params = [NSDictionary dictionary];
  launch_options = [NSDictionary dictionaryWithObject:@YES
                                               forKey:api->SBSApplicationLaunchOptionUnlockDeviceKey];

  if (spawn_options->has_argv)
    goto argv_not_supported;

  if (spawn_options->has_envp)
    goto envp_not_supported;

  if (spawn_options->has_env)
    goto env_not_supported;

  if (strlen (spawn_options->cwd) > 0)
    goto cwd_not_supported;

  if (spawn_options->stdio != TELCO_STDIO_INHERIT)
    goto stdio_not_supported;

  aslr_value = g_hash_table_lookup (spawn_options->aux, "aslr");
  if (aslr_value != NULL && !telco_parse_aslr_option (aslr_value, &aslr, &error))
    goto failure;
  if (aslr == TELCO_ASLR_DISABLE)
    goto aslr_not_supported;

  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^
  {
    UInt32 res;
    GError * error = NULL;

    telco_kill_application (identifier);

    if (url != nil)
    {
      res = api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions (
          identifier,
          url,
          params,
          launch_options,
          NO);
    }
    else
    {
      res = api->SBSLaunchApplicationWithIdentifierAndLaunchOptions (
          identifier,
          launch_options,
          NO);
    }

    if (res != 0)
    {
      error = g_error_new (
          TELCO_ERROR,
          TELCO_ERROR_NOT_SUPPORTED,
          "Unable to launch iOS app via SBS: %s",
          [api->SBSApplicationLaunchingErrorString (res) UTF8String]);
    }

    on_complete (NULL, error, on_complete_target);
  });

  return;

argv_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'argv' option is not supported when spawning apps on this version of iOS");
    goto failure;
  }
envp_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'envp' option is not supported when spawning iOS apps, use the 'env' option instead");
    goto failure;
  }
env_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'env' option is not supported when spawning apps on this version of iOS");
    goto failure;
  }
cwd_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'cwd' option is not supported when spawning iOS apps");
    goto failure;
  }
stdio_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Redirected stdio is not supported when spawning apps on this version of iOS");
    goto failure;
  }
aslr_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Disabling ASLR is not supported when spawning apps on this version of iOS");
    goto failure;
  }
failure:
  {
    on_complete (NULL, error, on_complete_target);
    return;
  }
}

#ifdef HAVE_TVOS

static void
telco_darwin_helper_backend_launch_using_lsaw (NSString * identifier, NSURL * url, TelcoHostSpawnOptions * spawn_options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  TelcoSpringboardApi * api;
  GError * error = NULL;
  BOOL opened = NO;

  if (spawn_options->has_argv)
    goto argv_not_supported;

  if (spawn_options->has_envp)
    goto envp_not_supported;

  if (spawn_options->has_env)
    goto env_not_supported;

  if (strlen (spawn_options->cwd) > 0)
    goto cwd_not_supported;

  if (spawn_options->stdio != TELCO_STDIO_INHERIT)
    goto stdio_not_supported;

  api = _telco_get_springboard_api ();

  telco_kill_application (identifier);

  if (url != nil)
    opened = [[api->LSApplicationWorkspace defaultWorkspace] openURL:url];
  else
    opened = [[api->LSApplicationWorkspace defaultWorkspace] openApplicationWithBundleID:identifier];
  if (!opened)
  {
    error = g_error_new (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unable to launch tvOS app via LSAW");
    goto failure;
  }

  on_complete (NULL, NULL, on_complete_target);
  return;

argv_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'argv' option is not supported when spawning tvOS apps");
    goto failure;
  }
envp_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'envp' option is not supported when spawning tvOS apps");
    goto failure;
  }
env_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'env' option is not supported when spawning tvOS apps");
    goto failure;
  }
cwd_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'cwd' option is not supported when spawning tvOS apps");
    goto failure;
  }
stdio_not_supported:
  {
    error = g_error_new_literal (
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "The 'stdio' option is not supported when spawning tvOS apps");
    goto failure;
  }
failure:
  {
    on_complete (NULL, error, on_complete_target);
    return;
  }
}

#endif

void
_telco_darwin_helper_backend_kill_process (guint pid)
{
  NSAutoreleasePool * pool;
  NSString * identifier;

  pool = [[NSAutoreleasePool alloc] init];

  identifier = _telco_get_springboard_api ()->SBSCopyDisplayIdentifierForProcessID (pid);
  if (identifier != nil)
  {
    telco_kill_application (identifier);

    [identifier release];
  }
  else
  {
    kill (pid, SIGKILL);
  }

  [pool release];
}

guint
_telco_darwin_helper_backend_kill_application (const gchar * identifier)
{
  guint killed_pid;
  NSAutoreleasePool * pool;

  pool = [[NSAutoreleasePool alloc] init];

  killed_pid = telco_kill_application ([NSString stringWithUTF8String:identifier]);

  [pool release];

  return killed_pid;
}

static guint
telco_kill_application (NSString * identifier)
{
  gint killed_pid = 0;
  TelcoSpringboardApi * api;
  GTimer * timer;
  const double kill_timeout = 3.0;
  struct kinfo_proc * processes = NULL;

  api = _telco_get_springboard_api ();

  if (api->FBSSystemService != nil)
  {
    FBSSystemService * service;

    service = [api->FBSSystemService sharedService];

    killed_pid = [service pidForApplication:identifier];
    if (killed_pid <= 0)
      goto beach;

    if (telco_has_active_prewarm (killed_pid))
    {
      kill (killed_pid, SIGKILL);
    }
    else
    {
      [service terminateApplication:identifier
                          forReason:FBProcessKillReasonUser
                          andReport:NO
                    withDescription:@"killed from Telco"];

    }

    timer = g_timer_new ();

    while ((killed_pid = [service pidForApplication:identifier]) > 0 && g_timer_elapsed (timer, NULL) < kill_timeout)
    {
      g_usleep (10000);
    }

    g_timer_destroy (timer);
  }
  else
  {
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t size;
    gboolean found;
    guint count, i;

    if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
      goto beach;

    while (TRUE)
    {
      size_t previous_size;
      gboolean still_too_small;

      processes = g_realloc (processes, size);

      previous_size = size;
      if (sysctl (mib, G_N_ELEMENTS (mib), processes, &size, NULL, 0) == 0)
        break;

      still_too_small = errno == ENOMEM;
      if (!still_too_small)
        goto beach;

      size = previous_size * 11 / 10;
    }

    count = size / sizeof (struct kinfo_proc);

    for (i = 0, found = FALSE; i != count && !found; i++)
    {
      struct kinfo_proc * p = &processes[i];
      UInt32 pid = p->kp_proc.p_pid;
      NSString * cur;

      cur = api->SBSCopyDisplayIdentifierForProcessID (pid);
      if ([cur isEqualToString:identifier])
      {
        kill (pid, SIGKILL);

        killed_pid = pid;
        timer = g_timer_new ();

        while (g_timer_elapsed (timer, NULL) < kill_timeout)
        {
          NSString * identifier_of_dying_process = api->SBSCopyDisplayIdentifierForProcessID (pid);
          if (identifier_of_dying_process == nil)
            break;
          [identifier_of_dying_process release];
          g_usleep (10000);
        }

        g_timer_destroy (timer);

        found = TRUE;
      }
      [cur release];
    }
  }

beach:
  g_free (processes);

  return killed_pid;
}

static gboolean
telco_has_active_prewarm (gint pid)
{
  gboolean prewarm_active = FALSE;
  int mib_argmax[] = { CTL_KERN, KERN_ARGMAX };
  int mib_args[] = { CTL_KERN, KERN_PROCARGS2, 0 };
  guint8 * buffer;
  size_t size;
  gint32 arg_max, argc;
  guint8 * cursor, * end;

  buffer = NULL;
  size = sizeof (arg_max);

  arg_max = 0;
  if (sysctl (mib_argmax, G_N_ELEMENTS (mib_argmax), &arg_max, &size, NULL, 0) != 0)
    goto beach;

  buffer = g_malloc (arg_max);
  if (buffer == NULL)
    goto beach;

  mib_args[2] = pid;
  size = arg_max;

  if (sysctl (mib_args, G_N_ELEMENTS (mib_args), buffer, &size, NULL, 0) != 0)
    goto beach;

  argc = *(gint32 *) buffer;
  end = buffer + size;
  cursor = buffer + sizeof (argc);

  /* Skip executable name */
  cursor = telco_skip_string (cursor, end);

  /* Skip args */
  while (argc-- != 0)
    cursor = telco_skip_string (cursor, end);

  /* Iterate environment */
  while (cursor != end)
  {
    if (strstr ((char *) cursor, "ActivePrewarm=1") != NULL)
    {
      prewarm_active = true;
      break;
    }
    cursor = telco_skip_string (cursor, end);
  }

beach:
  g_free (buffer);

  return prewarm_active;
}

static guint8 *
telco_skip_string (guint8 * cursor, guint8 * end)
{
  while (cursor != end && *cursor != '\0')
    cursor++;

  return ++cursor;
}

static NSArray *
telco_argv_to_arguments_array (gchar * const * argv, gint argv_length)
{
  NSMutableArray * result;
  gint i;

  result = [NSMutableArray arrayWithCapacity:argv_length];
  for (i = 1; i < argv_length; i++)
    [result addObject:[NSString stringWithUTF8String:argv[i]]];

  return result;
}

static NSDictionary *
telco_envp_to_environment_dictionary (gchar * const * envp, gint envp_length)
{
  NSMutableDictionary * result;
  gint i;

  result = [NSMutableDictionary dictionaryWithCapacity:envp_length];
  for (i = 0; i != envp_length; i++)
  {
    const gchar * pair, * equals_sign, * name_start, * value_start;
    NSUInteger name_size, value_size;
    NSString * name, * value;

    pair = envp[i];

    equals_sign = strchr (pair, '=');
    if (equals_sign == NULL)
      continue;

    name_start = pair;
    name_size = equals_sign - name_start;

    value_start = equals_sign + 1;
    value_size = pair + strlen (pair) - value_start;

    name = [[NSString alloc] initWithBytes:name_start
                                    length:name_size
                                  encoding:NSUTF8StringEncoding];
    value = [[NSString alloc] initWithBytes:value_start
                                     length:value_size
                                   encoding:NSUTF8StringEncoding];

    [result setObject:value forKey:name];

    [value release];
    [name release];
  }

  return result;
}

gboolean
telco_darwin_helper_backend_is_application_process (guint pid)
{
  gboolean is_app;
  gchar path[PROC_PIDPATHINFO_MAXSIZE];
  GumDarwinModule * module;

  if (proc_pidpath (pid, path, sizeof (path)) <= 0)
    return FALSE;

  module = gum_darwin_module_new_from_file (path, GUM_CPU_INVALID, GUM_PTRAUTH_INVALID, GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY, NULL);
  if (module == NULL)
    return FALSE;

  is_app = FALSE;
  gum_darwin_module_enumerate_dependencies (module, (GumFoundDependencyFunc) telco_find_uikit, &is_app);

  g_object_unref (module);

  return is_app;
}

static gboolean
telco_find_uikit (const GumDependencyDetails * details, gboolean * has_uikit)
{
  *has_uikit = strcmp (details->name, "/System/Library/Frameworks/UIKit.framework/UIKit") == 0;
  return !*has_uikit;
}

#else

void
_telco_darwin_helper_backend_launch (const gchar * identifier, TelcoHostSpawnOptions * options,
    TelcoDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  GError * error;

  error = g_error_new_literal (
      TELCO_ERROR,
      TELCO_ERROR_NOT_SUPPORTED,
      "Not yet able to launch apps on Mac");

  on_complete (NULL, error, on_complete_target);
}

void
_telco_darwin_helper_backend_kill_process (guint pid)
{
  kill (pid, SIGKILL);
}

guint
_telco_darwin_helper_backend_kill_application (const gchar * identifier)
{
  return 0;
}

gboolean
telco_darwin_helper_backend_is_application_process (guint pid)
{
  return FALSE;
}

#endif

gboolean
_telco_darwin_helper_backend_is_suspended (guint task, GError ** error)
{
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO_COUNT;
  const gchar * failed_operation;
  int retries = 3;
  kern_return_t kr;

  while (retries-- != 0)
  {
    kr = task_info (task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count);
    if (kr == KERN_SUCCESS || kr == MACH_SEND_INVALID_DEST)
      break;
  }

  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "task_info");

  return info.suspend_count >= 1;

mach_failure:
  {
    if (kr == MACH_SEND_INVALID_DEST)
    {
      g_set_error (error,
          TELCO_ERROR,
          TELCO_ERROR_PROCESS_NOT_FOUND,
          "Mach task is gone");
    }
    else
    {
      g_set_error (error,
          TELCO_ERROR,
          TELCO_ERROR_NOT_SUPPORTED,
          "Unexpected error while interrogating target process (%s returned '%s')",
          failed_operation, mach_error_string (kr));
    }
    return FALSE;
  }
}

void
telco_darwin_helper_backend_resume_process (guint task, GError ** error)
{
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO_COUNT;

  if (task_info (task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count) != KERN_SUCCESS)
    goto process_not_found;

  if (info.suspend_count <= 0)
    goto process_not_suspended;

  task_resume (task);

  return;

process_not_found:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_PROCESS_NOT_FOUND,
        "No such process");
    return;
  }
process_not_suspended:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_INVALID_OPERATION,
        "Process is not suspended");
    return;
  }
}

void
telco_darwin_helper_backend_resume_process_fast (guint task, GError ** error)
{
  kern_return_t kr;

  kr = task_resume (task);
  if (kr != KERN_SUCCESS)
    goto unexpected_error;

  return;

unexpected_error:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while resuming process: %s",
        mach_error_string (kr));
    return;
  }
}

void *
_telco_darwin_helper_backend_create_spawn_instance (TelcoDarwinHelperBackend * self, guint pid)
{
  TelcoSpawnInstance * instance;

  instance = telco_spawn_instance_new (self);
  instance->pid = pid;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instances), GUINT_TO_POINTER (pid), instance);

  return instance;
}

void
_telco_darwin_helper_backend_prepare_spawn_instance_for_injection (TelcoDarwinHelperBackend * self, void * opaque_instance, guint task, GError ** error)
{
  TelcoSpawnInstance * instance = opaque_instance;
  TelcoHelperContext * ctx = self->context;
  const gchar * failed_operation;
  kern_return_t kr;
  mach_port_t self_task, child_thread;
  guint page_size;
  thread_act_array_t threads;
  guint i;
  mach_msg_type_number_t thread_count = 0;
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumAddress dyld_start, dyld_granularity, dyld_chunk, dyld_header;
  GumAddress modern_entry_address, legacy_entry_address;
  const gchar * launch_with_closure_names[] = {
    "__ZN4dyldL17launchWithClosureEPKN5dyld37closure13LaunchClosureEPK15DyldSharedCachePKNS0_11MachOLoadedEmiPPKcSD_SD_R11DiagnosticsPmSG_PbSH_",
    "__ZN4dyldL17launchWithClosureEPKN5dyld312launch_cache13binary_format7ClosureEPK15DyldSharedCachePK11mach_headermiPPKcSE_SE_PmSF_",
    "__ZN4dyldL17launchWithClosureEPKN5dyld37closure13LaunchClosureEPK15DyldSharedCachePKNS0_11MachOLoadedEmiPPKcSD_SD_PmSE_",
  };
  GumDarwinModule * dyld;
  const GumDarwinSegment * segment;
  TelcoExceptionPortSet * previous_ports;
  dispatch_source_t source;

  /*
   * We POSIX_SPAWN_START_SUSPENDED which means that the kernel will create
   * the task and its main thread, with the main thread's instruction pointer
   * pointed at __dyld_start. At this point neither dyld nor libc have been
   * initialized, so we won't be able to inject telco-agent at this point.
   *
   * So here's what we'll do before we try to inject our dylib:
   * - Get hold of the main thread to read its instruction pointer, which will
   *   tell us where dyld is in memory.
   * - Walk backwards to find dyld's Mach-O header.
   * - Walk its symbols and find a function that's called at a point where the process is
   *   sufficiently initialized to load telco-agent, but still early enough so the app's
   *   initializer(s) didn't get a chance to run.
   * - For processes using dyld v3's closure support we put a hardware breakpoint inside
   *   dyld::launchWithClosure() right after setInitialImageList() has been called.
   *   At that point we have a fully initialized libSystem and are ready to go.
   *   For all other processes we also put a breakpoint on dyld::initializeMainExecutable().
   *   At the beginning of this function dyld is initialized but libSystem is still missing.
   * - Swap out the thread's exception ports with our own.
   * - Resume the task.
   * - Wait until we get a message on our exception port, meaning one of our two breakpoints
   *   was hit.
   * - If the breakpoint hit was the one in dyld::launchWithClosure(), then great, we are done.
   *   Otherwise we hijack the thread's instruction pointer to call:
   *   dlopen("/usr/lib/libSystem.B.dylib", RTLD_GLOBAL | RTLD_LAZY)
   *   and then return back to the beginning of initializeMainExecutable() and restore the
   *   previous thread state.
   * - Swap back the thread's orginal exception ports.
   * - Clear the hardware breakpoint by restoring the thread's debug registers.
   *
   * For processes not using the new closure support it's actually more complex than that,
   * because:
   * - This doesn't work on newer versions of dyld because to call dlopen() it's
   *   necessary to registerThreadHelpers() first, which is normally done by libSystem
   *   itself during its initialization.
   * - To overcome this catch-22 we alloc a fake LibSystemHelpers object and register
   *   it (also by hijacking thread's instruction pointer as described above).
   * - On older dyld versions, registering helpers before loading libSystem led to
   *   crashes, so we detect this condition and unset the helpers before calling dlopen(),
   *   by writing a NULL directly into the global dyld::gLibSystemHelpers because in
   *   some dyld versions calling registerThreadHelpers(NULL) causes a NULL dereference.
   * - At the end of dlopen(), we set the global "libSystemInitialized" flag present in
   *   the global dyld::qProcessInfo structure, because on newer dyld versions that doesn't
   *   happen automatically due to the presence of our fake helpers.
   * - One of the functions provided by the helper should return a buffer for the errors,
   *   but since our fake helpers object implements its functions only using a return,
   *   it will not return any buffer. To avoid this to happen, we set a breakpoint also
   *   on dyld:dlerrorClear function and inject an immediate return,
   *   effectively disabling the function.
   * - At the end of dlopen() we finally deallocate our fake helpers (because now they've
   *   been replaced by real libSystem ones) and the string we used as a parameter for dlopen.
   *
   * When DYLD_INSERT_LIBRARIES variable is set, there's a special case to handle:
   * - On newer dyld versions, the code path triggered by dlopen() is different and may
   *   fail if "libSystemInitialized" is still false when loading libSystem dependencies
   *   (most notably libc++.1.dylib).
   * - To work around this, just before calling dlopen() we place a breakpoint at the
   *   beginning of strcmp() and force it to return 0 when called from the
   *   ImageLoaderMachO::doModInitFunctions() method.
   * - This tweak isn't necessary on older dyld versions for which we don't need helpers,
   *   because the failing check isn't there and because it wouldn't have failed since
   *   the libSystemInitialized variable gets set early on in our flow.
   *
   * Also, starting with Mojave and iOS 12 the dlopen() symbol is gone and we have to use
   * dlopen_internal().
   *
   * Update, 2021: Monterey and iOS 15 introduced dyld v4, which we now have preliminary
   *               support for. Search for “TELCO_DYLD_V4_PLUS” for more details.
   *
   * Then later when resume() is called:
   * - Send a response to the message we got on our exception port, so the
   *   kernel considers it handled and resumes the main thread for us.
   */

  self_task = mach_task_self ();

  if (!gum_darwin_cpu_type_from_pid (instance->pid, &instance->cpu_type))
    goto cpu_probe_failed;

  if (!gum_darwin_query_page_size (task, &page_size))
    goto page_size_probe_failed;

  kr = task_threads (task, &threads, &thread_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "task_threads");

  child_thread = threads[0];
  instance->thread = child_thread;
  mach_port_mod_refs (self_task, task, MACH_PORT_RIGHT_SEND, 1);
  instance->task = task;

  for (i = 1; i < thread_count; i++)
    mach_port_deallocate (self_task, threads[i]);
  vm_deallocate (self_task, (vm_address_t) threads, thread_count * sizeof (thread_t));
  threads = NULL;

  kr = telco_get_thread_state (child_thread, state_flavor, &state, &state_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "get_thread_state");

#ifdef HAVE_I386
  dyld_start = (instance->cpu_type == GUM_CPU_AMD64) ? state.uts.ts64.__rip : state.uts.ts32.__eip;
#else
  dyld_start = (instance->cpu_type == GUM_CPU_ARM64) ? __darwin_arm_thread_state64_get_pc (state.ts_64) : state.ts_32.__pc;
#endif

  dyld_header = 0;
  dyld_granularity = 4096;
  for (dyld_chunk = (dyld_start & (dyld_granularity - 1)) == 0 ? (dyld_start - dyld_granularity) : (dyld_start & ~(dyld_granularity - 1));
      dyld_header == 0;
      dyld_chunk -= dyld_granularity)
  {
    guint32 * magic;

    magic = (guint32 *) gum_darwin_read (task, dyld_chunk, sizeof (magic), NULL);
    if (magic == NULL)
      goto dyld_probe_failed;

    if (*magic == MH_MAGIC || *magic == MH_MAGIC_64)
      dyld_header = dyld_chunk;

    g_free (magic);
  }

  dyld = gum_darwin_module_new_from_memory ("/usr/lib/dyld", task, dyld_header, GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  instance->dyld = dyld;
  instance->dyld_size = 0;
  i = 0;
  while ((segment = gum_darwin_module_get_nth_segment (dyld, i++)) != NULL)
  {
    if (strcmp (segment->name, "__TEXT") == 0)
    {
      instance->dyld_size = segment->vm_size;
      break;
    }
  }

  modern_entry_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN5dyld44APIs19_libdyld_initializeEPKNS_16LibSystemHelpersE");
  instance->dyld_flavor = (modern_entry_address != 0) ? TELCO_DYLD_V4_PLUS : TELCO_DYLD_V3_MINUS;
  if (instance->dyld_flavor == TELCO_DYLD_V4_PLUS)
  {
    instance->modern_entry_address = modern_entry_address;
    legacy_entry_address = 0;

    instance->info_ptr_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZL12sProcessInfo");
    if (instance->info_ptr_address == 0)
    {
      instance->info_ptr_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN5dyld412gProcessInfoE");
      if (instance->info_ptr_address == 0)
      {
        instance->info_ptr_address = gum_darwin_module_resolve_symbol_address (dyld, "_gProcessInfo");
        if (instance->info_ptr_address == 0)
          goto dyld_probe_failed;
      }
    }
  }
  else
  {
    GumAddress launch_with_closure_address;

    legacy_entry_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld24initializeMainExecutableEv");
    modern_entry_address = 0;

    launch_with_closure_address = 0;
    for (i = 0; i != G_N_ELEMENTS (launch_with_closure_names) && launch_with_closure_address == 0; i++)
    {
      launch_with_closure_address = gum_darwin_module_resolve_symbol_address (dyld, launch_with_closure_names[i]);
    }

    if (launch_with_closure_address != 0)
    {
      modern_entry_address = telco_find_run_initializers_call (task, instance->cpu_type, launch_with_closure_address);
    }

    instance->modern_entry_address = modern_entry_address;

    instance->dlopen_address = gum_darwin_module_resolve_symbol_address (dyld, "_dlopen");
    if (instance->dlopen_address == 0)
      instance->dlopen_address = gum_darwin_module_resolve_symbol_address (dyld, "_dlopen_internal");
    instance->register_helpers_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZL21registerThreadHelpersPKN4dyld16LibSystemHelpersE");
    instance->dlerror_clear_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZL12dlerrorClearv");
    instance->info_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld12gProcessInfoE");
    instance->helpers_ptr_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld17gLibSystemHelpersE");
    instance->do_modinit_strcmp_checks = telco_find_modinit_strcmp_checks (task, dyld);

    if (legacy_entry_address == 0 || instance->dlopen_address == 0 || instance->register_helpers_address == 0 ||
        instance->info_address == 0 || instance->do_modinit_strcmp_checks == NULL)
    {
      goto dyld_probe_failed;
    }

    if (instance->cpu_type == GUM_CPU_ARM)
    {
      instance->dlopen_address |= 1;
      instance->register_helpers_address |= 1;
    }

    instance->ret_gadget = telco_find_function_end (task, instance->cpu_type, instance->register_helpers_address, 128);
    if (instance->ret_gadget == 0)
      goto dyld_probe_failed;

    if (instance->cpu_type == GUM_CPU_ARM)
      instance->ret_gadget |= 1;
  }

  instance->ret_state = TELCO_RET_FROM_HELPER;

  kr = telco_get_debug_state (child_thread, &instance->previous_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "telco_get_debug_state");

  memcpy (&instance->breakpoint_debug_state, &instance->previous_debug_state, sizeof (instance->breakpoint_debug_state));
  i = 0;
  if (legacy_entry_address != 0)
    telco_spawn_instance_set_nth_breakpoint (instance, i++, legacy_entry_address, TELCO_BREAKPOINT_REPEAT_ALWAYS);
  if (modern_entry_address != 0)
    telco_spawn_instance_set_nth_breakpoint (instance, i++, modern_entry_address, TELCO_BREAKPOINT_REPEAT_ALWAYS);
  if (instance->dyld_flavor == TELCO_DYLD_V4_PLUS)
  {
    GumAddress restart_with_dyld_in_cache = gum_darwin_module_resolve_symbol_address (dyld,
        "__ZN5dyld422restartWithDyldInCacheEPKNS_10KernelArgsEPKN5dyld39MachOFileEPv");
    if (restart_with_dyld_in_cache != 0)
      telco_spawn_instance_set_nth_breakpoint (instance, i++, restart_with_dyld_in_cache, TELCO_BREAKPOINT_REPEAT_NEVER);
  }

  kr = telco_set_debug_state (child_thread, &instance->breakpoint_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "telco_set_debug_state");

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &instance->server_port);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate server");

  kr = mach_port_insert_right (self_task, instance->server_port, instance->server_port, MACH_MSG_TYPE_MAKE_SEND);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_insert_right server");

  previous_ports = &instance->previous_ports;
  kr = thread_swap_exception_ports (child_thread,
#if __has_feature (ptrauth_calls)
      EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT,
#else
      EXC_MASK_BREAKPOINT,
#endif
      instance->server_port,
      EXCEPTION_DEFAULT,
      state_flavor,
      previous_ports->masks,
      &previous_ports->count,
      previous_ports->ports,
      previous_ports->behaviors,
      previous_ports->flavors);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_swap_exception_ports");

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, telco_spawn_instance_on_server_recv);
  dispatch_resume (source);

  return;

cpu_probe_failed:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing CPU type of target process");
    goto failure;
  }
page_size_probe_failed:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing page size of target process");
    goto failure;
  }
dyld_probe_failed:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing dyld of target process");
    goto failure;
  }
mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing target process for injection (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto failure;
  }
failure:
  {
    return;
  }
}

void
_telco_darwin_helper_backend_resume_spawn_instance (TelcoDarwinHelperBackend * self, void * instance)
{
  telco_spawn_instance_resume (instance);
}

void
_telco_darwin_helper_backend_free_spawn_instance (TelcoDarwinHelperBackend * self, void * instance)
{
  telco_spawn_instance_free (instance);
}

guint
_telco_darwin_helper_backend_inject_into_task (TelcoDarwinHelperBackend * self, guint pid, guint task, const gchar * path_or_name, TelcoMappedLibraryBlob * blob,
    const gchar * entrypoint, const gchar * data, GError ** error)
{
  guint result = 0;
  mach_port_t self_task;
  TelcoInjectInstance * instance;
  GumDarwinModuleResolver * resolver = NULL;
  GumDarwinMapper * mapper = NULL;
  GError * io_error = NULL;
  TelcoDarwinModuleDetails mapped_module;
  TelcoAgentDetails details = { 0, };
  guint page_size;
  TelcoInjectPayloadLayout layout;
  kern_return_t kr;
  const gchar * failed_operation;
  guint base_payload_size;
  mach_vm_address_t payload_address = 0;
  mach_vm_address_t agent_context_address = 0;
  mach_vm_address_t data_address;
  vm_prot_t cur_protection, max_protection;
  guint8 mach_stub_code[512] = { 0, };
  guint8 pthread_stub_code[512] = { 0, };
  TelcoAgentContext agent_ctx;
  GumAddress pc, sp, data_arg;

  self_task = mach_task_self ();

  instance = telco_inject_instance_new (self, self->next_id++, pid);
  mach_port_mod_refs (self_task, task, MACH_PORT_RIGHT_SEND, 1);
  instance->task = task;

  resolver = gum_darwin_module_resolver_new (task, &io_error);
  if (io_error != NULL)
    goto gum_failure;

  details.pid = pid;
  details.dylib_path = (blob == NULL) ? path_or_name : NULL;
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;
  details.cpu_type = resolver->cpu_type;

  page_size = resolver->page_size;

#ifdef HAVE_MAPPER
  if (blob != NULL)
  {
    mapper = gum_darwin_mapper_new_take_blob (path_or_name,
        g_bytes_new_with_free_func (GSIZE_TO_POINTER (blob->address), blob->size,
            (GDestroyNotify) telco_mapper_library_blob_deallocate, telco_mapped_library_blob_dup (blob)),
        resolver, &io_error);
  }
  else
  {
    mapper = gum_darwin_mapper_new_from_file (path_or_name, resolver, &io_error);
  }
  if (io_error != NULL)
    goto gum_failure;
#else
  (void) telco_mapper_library_blob_deallocate;
#endif

  layout.stack_guard_size = page_size;
  layout.stack_size = 32 * 1024;

  layout.code_offset = 0;
  layout.mach_code_offset = 0;
  layout.pthread_code_offset = 512;
  layout.data_offset = page_size;
  layout.data_size = GUM_ALIGN_SIZE (sizeof (TelcoAgentContext), page_size);
  layout.stack_guard_offset = layout.data_offset + layout.data_size;
  layout.stack_bottom_offset = layout.stack_guard_offset + layout.stack_guard_size;
  layout.stack_top_offset = layout.stack_bottom_offset + layout.stack_size;

  base_payload_size = layout.stack_top_offset;

  instance->payload_size = base_payload_size;
  if (mapper != NULL)
    instance->payload_size += gum_darwin_mapper_size (mapper);

  kr = mach_vm_allocate (task, &payload_address, instance->payload_size, VM_FLAGS_ANYWHERE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_allocate(payload)");
  instance->payload_address = payload_address;

  kr = mach_vm_allocate (self_task, &agent_context_address, layout.data_size, VM_FLAGS_ANYWHERE);
  g_assert (kr == KERN_SUCCESS);
  instance->agent_context = (TelcoAgentContext *) agent_context_address;
  instance->agent_context_size = layout.data_size;

  data_address = payload_address + layout.data_offset;
  kr = mach_vm_remap (task, &data_address, layout.data_size, 0, VM_FLAGS_OVERWRITE, self_task, agent_context_address,
      FALSE, &cur_protection, &max_protection, VM_INHERIT_SHARE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(data)");
  instance->remote_agent_context = data_address;

  if (mapper != NULL)
  {
    GumDarwinModule * module;

    gum_darwin_mapper_map (mapper, payload_address + base_payload_size, &io_error);
    if (io_error != NULL)
      goto gum_failure;

    g_object_get (mapper, "module", &module, NULL);
    mapped_module._mach_header_address = module->base_address;
    mapped_module._uuid = module->uuid;
    mapped_module._path = module->name;
    g_object_unref (module);

    instance->is_mapped = TRUE;
  }

  kr = mach_vm_protect (task, payload_address + layout.stack_guard_offset, layout.stack_guard_size, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");

  if (!telco_agent_context_init (&agent_ctx, &details, &layout, payload_address, instance->payload_size, resolver, mapper, error))
    goto failure;

  telco_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, resolver, mapper);

  telco_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, resolver, mapper);

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    kr = mach_vm_write (task, payload_address + layout.mach_code_offset,
        (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(mach_stub_code)");

    kr = mach_vm_write (task, payload_address + layout.pthread_code_offset,
        (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(pthread_stub_code)");

    kr = mach_vm_protect (task, payload_address + layout.code_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;
    mach_vm_address_t code_address;

    segment = gum_code_segment_new (page_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page + layout.mach_code_offset, mach_stub_code, sizeof (mach_stub_code));
    memcpy (scratch_page + layout.pthread_code_offset, pthread_stub_code, sizeof (pthread_stub_code));

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, page_size, scratch_page);

    code_address = payload_address + layout.code_offset;
    kr = mach_vm_remap (task, &code_address, page_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(code)");
  }

  kr = mach_vm_write (task, payload_address + layout.data_offset, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(data)");

  kr = mach_vm_protect (task, payload_address + layout.data_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");

  pc = payload_address + layout.mach_code_offset;
  sp = payload_address + layout.stack_top_offset;
  data_arg = payload_address + layout.data_offset;

#ifdef HAVE_I386
  {
    x86_thread_state_t * state = &instance->thread_state;

    bzero (state, sizeof (x86_thread_state_t));

    if (details.cpu_type == GUM_CPU_AMD64)
    {
      x86_thread_state64_t * ts;

      state->tsh.flavor = x86_THREAD_STATE64;
      state->tsh.count = x86_THREAD_STATE64_COUNT;

      ts = &state->uts.ts64;

      ts->__rbx = data_arg;

      ts->__rsp = sp;
      ts->__rip = pc;
    }
    else
    {
      x86_thread_state32_t * ts;

      state->tsh.flavor = x86_THREAD_STATE32;
      state->tsh.count = x86_THREAD_STATE32_COUNT;

      ts = &state->uts.ts32;

      ts->__ebx = data_arg;

      ts->__esp = sp;
      ts->__eip = pc;
    }

    instance->thread_state_data = (thread_state_t) state;
    instance->thread_state_count = x86_THREAD_STATE_COUNT;
    instance->thread_state_flavor = x86_THREAD_STATE;
  }
#else
  if (details.cpu_type == GUM_CPU_ARM64)
  {
    arm_unified_thread_state_t * state64 = &instance->thread_state64;
    arm_thread_state64_t * ts;
    GumAddress dummy_lr;

    bzero (state64, sizeof (arm_unified_thread_state_t));

    state64->ash.flavor = ARM_THREAD_STATE64;
    state64->ash.count = ARM_THREAD_STATE64_COUNT;

    ts = &state64->ts_64;

    ts->__x[20] = data_arg;

    __darwin_arm_thread_state64_set_sp (*ts, sp);
    dummy_lr = 0xcafebabe;
    __darwin_arm_thread_state64_set_lr_fptr (*ts, GSIZE_TO_POINTER (gum_sign_code_address (dummy_lr)));
    __darwin_arm_thread_state64_set_pc_fptr (*ts, GSIZE_TO_POINTER (gum_sign_code_address (pc)));

    instance->thread_state_data = (thread_state_t) state64;
    instance->thread_state_count = ARM_UNIFIED_THREAD_STATE_COUNT;
    instance->thread_state_flavor = ARM_UNIFIED_THREAD_STATE;
  }
  else
  {
    arm_thread_state_t * state32 = &instance->thread_state32;

    bzero (state32, sizeof (arm_thread_state_t));

    state32->__r[7] = data_arg;

    state32->__sp = sp;
    state32->__lr = 0xcafebabe;
    state32->__pc = pc;
    state32->__cpsr = TELCO_PSR_THUMB;

    instance->thread_state_data = (thread_state_t) state32;
    instance->thread_state_count = ARM_THREAD_STATE_COUNT;
    instance->thread_state_flavor = ARM_THREAD_STATE;
  }
#endif

  if (!telco_inject_instance_start_thread (instance, error))
    goto failure;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (instance->id), instance);

  instance->is_loaded = TRUE;
  _telco_darwin_helper_backend_on_inject_instance_loaded (self, instance->id, instance->pid, (mapper != NULL) ? &mapped_module : NULL);

  result = instance->id;
  goto beach;

gum_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "%s",
        io_error->message);
    g_error_free (io_error);
    goto failure;
  }
mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (kr));
    goto failure;
  }
failure:
  {
    telco_inject_instance_free (instance);
    goto beach;
  }
beach:
  {
    g_clear_object (&mapper);
    g_clear_object (&resolver);

    return result;
  }
}

void
_telco_darwin_helper_backend_demonitor (TelcoDarwinHelperBackend * self, void * raw_instance)
{
  TelcoInjectInstance * instance = raw_instance;

  dispatch_release (instance->thread_monitor_source);
  instance->thread_monitor_source = NULL;

  mach_port_deallocate (mach_task_self (), instance->thread);
  instance->thread = MACH_PORT_NULL;
}

guint
_telco_darwin_helper_backend_demonitor_and_clone_injectee_state (TelcoDarwinHelperBackend * self, void * raw_instance)
{
  TelcoInjectInstance * instance = raw_instance;
  TelcoInjectInstance * clone;

  dispatch_release (instance->thread_monitor_source);
  instance->thread_monitor_source = NULL;

  mach_port_deallocate (mach_task_self (), instance->thread);
  instance->thread = MACH_PORT_NULL;

  clone = telco_inject_instance_clone (instance, self->next_id++);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (clone->id), clone);

  return clone->id;
}

void
_telco_darwin_helper_backend_recreate_injectee_thread (TelcoDarwinHelperBackend * self, void * raw_instance, guint pid, guint task, GError ** error)
{
  TelcoInjectInstance * instance = raw_instance;
  TelcoAgentContext * agent_context = instance->agent_context;
  mach_port_t self_task;
  gboolean is_uninitialized_clone;
  const gchar * failed_operation;
  kern_return_t kr;

  agent_context->unload_policy = TELCO_UNLOAD_POLICY_IMMEDIATE;
  agent_context->task = MACH_PORT_NULL;
  agent_context->mach_thread = MACH_PORT_NULL;
  agent_context->posix_thread = MACH_PORT_NULL;
  agent_context->posix_tid = 0;

  self_task = mach_task_self ();

  is_uninitialized_clone = instance->task == MACH_PORT_NULL;

  if (is_uninitialized_clone)
  {
    mach_vm_address_t data_address;
    vm_prot_t cur_protection, max_protection;

    mach_port_mod_refs (self_task, task, MACH_PORT_RIGHT_SEND, 1);
    instance->task = task;

    data_address = instance->remote_agent_context;
    kr = mach_vm_remap (task, &data_address, instance->agent_context_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) agent_context,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_SHARE);
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(data)");
  }

  if (!telco_inject_instance_start_thread (instance, error))
    goto failure;

  goto beach;

mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while recreating thread in process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (kr));
    goto failure;
  }
failure:
  {
    _telco_darwin_helper_backend_destroy_inject_instance (self, instance->id);
    goto beach;
  }
beach:
  {
    return;
  }
}

static gboolean
telco_inject_instance_start_thread (TelcoInjectInstance * self, GError ** error)
{
  gboolean success = FALSE;
  kern_return_t kr;
  const gchar * failed_operation;
  TelcoHelperContext * ctx = self->backend->context;
  dispatch_source_t source;

  kr = thread_create (self->task, &self->thread);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_create");

  kr = telco_set_thread_state (self->thread, self->thread_state_flavor, self->thread_state_data, self->thread_state_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "set_thread_state");

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, self->thread, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  self->thread_monitor_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source, telco_inject_instance_on_mach_thread_dead);
  dispatch_resume (source);

  kr = thread_resume (self->thread);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_resume");

  success = TRUE;

  goto beach;

mach_failure:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while starting thread (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto beach;
  }
beach:
  {
    return success;
  }
}

static void
telco_inject_instance_on_mach_thread_dead (void * context)
{
  TelcoInjectInstance * self = context;
  mach_port_t posix_thread_right_in_remote_task = self->agent_context->posix_thread;
  mach_port_t posix_thread_right_in_local_task = MACH_PORT_NULL;

  if (posix_thread_right_in_remote_task != MACH_PORT_NULL)
  {
    gboolean port_might_be_guarded, denied_by_modern_xnu;

    self->agent_context->posix_thread = MACH_PORT_NULL;

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
    port_might_be_guarded = gum_darwin_check_xnu_version (7938, 0, 0);
#else
    port_might_be_guarded = FALSE;
#endif

    if (port_might_be_guarded)
    {
      denied_by_modern_xnu = TRUE;
    }
    else
    {
      kern_return_t kr;
      mach_msg_type_name_t acquired_type;

      kr = mach_port_extract_right (self->task, posix_thread_right_in_remote_task, MACH_MSG_TYPE_MOVE_SEND,
          &posix_thread_right_in_local_task, &acquired_type);
      denied_by_modern_xnu = kr == KERN_INVALID_CAPABILITY;
    }

    if (denied_by_modern_xnu)
    {
      posix_thread_right_in_local_task = telco_obtain_thread_port_for_thread_id (self->task, self->agent_context->posix_tid);

      mach_port_deallocate (self->task, posix_thread_right_in_remote_task);
    }

    if (posix_thread_right_in_local_task == MACH_PORT_DEAD)
      posix_thread_right_in_local_task = MACH_PORT_NULL;
  }

  _telco_darwin_helper_backend_on_mach_thread_dead (self->backend, self->id, GSIZE_TO_POINTER (posix_thread_right_in_local_task));
}

void
_telco_darwin_helper_backend_join_inject_instance_posix_thread (TelcoDarwinHelperBackend * self, void * instance, void * posix_thread)
{
  telco_inject_instance_join_posix_thread (instance, GPOINTER_TO_SIZE (posix_thread));
}

static void
telco_inject_instance_join_posix_thread (TelcoInjectInstance * self, mach_port_t posix_thread)
{
  TelcoHelperContext * ctx = self->backend->context;
  mach_port_t self_task;
  dispatch_source_t source;

  self_task = mach_task_self ();

  mach_port_deallocate (self_task, self->thread);
  self->thread = posix_thread;

  dispatch_release (self->thread_monitor_source);
  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, self->thread, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  self->thread_monitor_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source, telco_inject_instance_on_posix_thread_dead);
  dispatch_resume (source);
}

static void
telco_inject_instance_on_posix_thread_dead (void * context)
{
  TelcoInjectInstance * self = context;

  _telco_darwin_helper_backend_on_posix_thread_dead (self->backend, self->id);
}

guint
_telco_darwin_helper_backend_get_pid_of_inject_instance (TelcoDarwinHelperBackend * self, void * instance)
{
  return ((TelcoInjectInstance *) instance)->pid;
}

void
_telco_darwin_helper_backend_free_inject_instance (TelcoDarwinHelperBackend * self, void * instance)
{
  telco_inject_instance_free (instance);
}

static TelcoSpawnInstance *
telco_spawn_instance_new (TelcoDarwinHelperBackend * backend)
{
  TelcoSpawnInstance * instance;
  guint i;

  instance = g_slice_new0 (TelcoSpawnInstance);
  instance->backend = backend;
  instance->thread = MACH_PORT_NULL;

  instance->server_port = MACH_PORT_NULL;
  instance->server_recv_source = NULL;

  instance->pending_request.thread.name = MACH_PORT_NULL;
  instance->pending_request.task.name = MACH_PORT_NULL;

  instance->breakpoint_phase = TELCO_BREAKPOINT_DETECT_FLAVOR;
  instance->single_stepping = -1;
  for (i = 0; i != TELCO_MAX_BREAKPOINTS; i++)
  {
    instance->breakpoints[i].address = 0;
    instance->breakpoints[i].repeat = TELCO_BREAKPOINT_REPEAT_NEVER;
  }

  for (i = 0; i != TELCO_MAX_PAGE_POOL; i++)
  {
    instance->page_pool[i].page_start = 0;
    instance->page_pool[i].scratch_page = 0;
  }

  return instance;
}

static void
telco_spawn_instance_free (TelcoSpawnInstance * instance)
{
  task_t self_task;
  TelcoExceptionPortSet * previous_ports;
  mach_msg_type_number_t port_index;

  self_task = mach_task_self ();

  if (instance->do_modinit_strcmp_checks != NULL)
    g_hash_table_unref (instance->do_modinit_strcmp_checks);

  mach_msg_destroy (&instance->pending_request.Head);

  previous_ports = &instance->previous_ports;
  for (port_index = 0; port_index != previous_ports->count; port_index++)
  {
    mach_port_deallocate (self_task, previous_ports->ports[port_index]);
  }
  if (instance->server_recv_source != NULL)
    dispatch_release (instance->server_recv_source);
  if (instance->server_port != MACH_PORT_NULL)
  {
    mach_port_mod_refs (self_task, instance->server_port, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs (self_task, instance->server_port, MACH_PORT_RIGHT_RECEIVE, -1);
  }

  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);

  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);

  if (instance->dyld != NULL)
    g_object_unref (instance->dyld);

  g_slice_free (TelcoSpawnInstance, instance);
}

static GumAddress
telco_spawn_instance_get_ret_gadget_address (TelcoSpawnInstance * self)
{
  if (self->cpu_type == GUM_CPU_ARM)
    return self->ret_gadget & ~GUM_ADDRESS (1);

  return self->ret_gadget;
}

static void
telco_spawn_instance_resume (TelcoSpawnInstance * self)
{
  if (self->breakpoint_phase != TELCO_BREAKPOINT_DONE)
  {
    guint task;
    GError * error = NULL;

    task = telco_darwin_helper_backend_task_for_pid (self->pid, &error);
    if (error == NULL)
    {
      telco_darwin_helper_backend_resume_process (task, &error);

      mach_port_deallocate (mach_task_self (), task);
    }

    g_clear_error (&error);

    return;
  }

  telco_spawn_instance_send_breakpoint_response (self);
}

static void
telco_spawn_instance_on_server_recv (void * context)
{
  TelcoSpawnInstance * self = context;
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  kern_return_t kr;
  GumAddress pc;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  GumDarwinUnifiedThreadState state;
  guint i, current_bp_index;
  TelcoBreakpoint * breakpoint = NULL;
  gboolean carry_on, pc_changed;

  telco_spawn_instance_receive_breakpoint_request (self);

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  {
    gboolean is_step_complete;

    is_step_complete = request->exception == EXC_BREAKPOINT && request->code[0] == EXC_ARM_BREAKPOINT && request->code[1] == 0;

    if ((self->single_stepping >= 0 && !is_step_complete) ||
        (self->single_stepping == -1 && is_step_complete))
    {
      telco_spawn_instance_send_breakpoint_response (self);
      return;
    }
  }
#endif

  kr = telco_get_thread_state (self->thread, state_flavor, &state, &state_count);
  if (kr != KERN_SUCCESS)
    return;

#if __has_feature (ptrauth_calls)
  {
    const GumAddress ret_gadget = telco_spawn_instance_get_ret_gadget_address (self);
    gboolean pc_may_need_fixup_due_to_ptrauth_failure;

    pc_may_need_fixup_due_to_ptrauth_failure = gum_strip_code_address (GUM_ADDRESS (state.ts_64.__opaque_pc)) == ret_gadget;
    if (pc_may_need_fixup_due_to_ptrauth_failure)
    {
      __darwin_arm_thread_state64_set_pc_fptr (state.ts_64, GSIZE_TO_POINTER (gum_sign_code_address (ret_gadget)));
    }
  }
#endif

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
    pc = state.uts.ts64.__rip;
  else
    pc = state.uts.ts32.__eip;
#else
  if (self->cpu_type == GUM_CPU_ARM64)
    pc = __darwin_arm_thread_state64_get_pc (state.ts_64);
  else
    pc = state.ts_32.__pc;
#endif

  if (self->single_stepping >= 0)
  {
    TelcoBreakpoint * bp = &self->breakpoints[self->single_stepping];

    telco_set_hardware_single_step (&self->breakpoint_debug_state, &state, FALSE, self->cpu_type);

    if (bp->repeat != TELCO_BREAKPOINT_REPEAT_ALWAYS)
      telco_spawn_instance_unset_nth_breakpoint (self, self->single_stepping);
    self->single_stepping = -1;

    for (i = 0; i != TELCO_MAX_BREAKPOINTS; i++)
    {
      TelcoBreakpoint * bp = &self->breakpoints[i];
      if (bp->repeat != TELCO_BREAKPOINT_REPEAT_NEVER)
        telco_spawn_instance_set_nth_breakpoint (self, i, bp->address, bp->repeat);
    }

    telco_set_thread_state (self->thread, state_flavor, &state, state_count);
    telco_set_debug_state (self->thread, &self->breakpoint_debug_state, self->cpu_type);

    telco_spawn_instance_send_breakpoint_response (self);

    return;
  }

  for (i = 0; i != TELCO_MAX_BREAKPOINTS; i++)
  {
    if ((self->breakpoints[i].address & ~1) == (pc & ~GUM_ADDRESS (1)))
    {
      current_bp_index = i;
      breakpoint = &self->breakpoints[i];
      break;
    }
  }

  if (breakpoint == NULL)
    goto unexpected_exception;

  carry_on = telco_spawn_instance_handle_breakpoint (self, breakpoint, &state);
  if (!carry_on)
    return;

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
    pc_changed = state.uts.ts64.__rip != pc;
  else
    pc_changed = state.uts.ts32.__eip != pc;
#else
  if (self->cpu_type == GUM_CPU_ARM64)
    pc_changed = __darwin_arm_thread_state64_get_pc (state.ts_64) != pc;
  else
    pc_changed = state.ts_32.__pc != pc;
#endif

  if (!pc_changed)
  {
    for (i = 0; i != TELCO_MAX_BREAKPOINTS; i++)
      telco_spawn_instance_disable_nth_breakpoint (self, i);

    telco_set_hardware_single_step (&self->breakpoint_debug_state, &state, TRUE, self->cpu_type);

    self->single_stepping = current_bp_index;
  }
  else if (breakpoint->repeat != TELCO_BREAKPOINT_REPEAT_ALWAYS)
  {
    telco_spawn_instance_unset_nth_breakpoint (self, current_bp_index);
  }

  telco_set_thread_state (self->thread, state_flavor, &state, state_count);
  telco_set_debug_state (self->thread, &self->breakpoint_debug_state, self->cpu_type);

  telco_spawn_instance_send_breakpoint_response (self);

  return;

unexpected_exception:
  {
    GString * message;
    GError * error;

    message = g_string_sized_new (128);

    g_string_append (message, "Unexpectedly hit ");

    switch (request->exception)
    {
      case EXC_BAD_ACCESS:
        g_string_append (message, "an invalid memory address");
        break;
      case EXC_BAD_INSTRUCTION:
        g_string_append (message, "a bad instruction");
        break;
      case EXC_ARITHMETIC:
        g_string_append (message, "an arithmetic error");
        break;
      case EXC_EMULATION:
        g_string_append (message, "an emulation error");
        break;
      case EXC_SOFTWARE:
        g_string_append (message, "a software exception");
        break;
      case EXC_BREAKPOINT:
        g_string_append (message, "an unknown breakpoint");
        break;
      case EXC_CRASH:
        g_string_append (message, "a crash");
        break;
      case EXC_RESOURCE:
        g_string_append (message, "a resource limit");
        break;
      case EXC_GUARD:
        g_string_append (message, "a guard");
        break;
      default:
        g_string_append_printf (message, "exception %d", request->exception);
        break;
    }

    if (request->codeCnt != 0)
    {
      mach_msg_type_number_t i;

      g_string_append (message, " with codes [");

      for (i = 0; i != request->codeCnt; i++)
      {
        if (i != 0)
          g_string_append_c (message, ',');
        g_string_append_printf (message, " 0x%x", request->code[i]);
      }

      g_string_append (message, " ]");
    }

    if (gum_darwin_module_is_address_in_text_section (self->dyld, pc))
    {
      g_string_append_printf (message, " at dyld!0x%zx", (size_t) (pc - self->dyld->base_address));
    }
    else
    {
      g_string_append_printf (message, " at 0x%zx", (size_t) pc);
    }

    g_string_append (message, " while initializing suspended process");

    error = g_error_new_literal (TELCO_ERROR, TELCO_ERROR_NOT_SUPPORTED, message->str);

    _telco_darwin_helper_backend_on_spawn_instance_error (self->backend, self->pid, error);

    g_error_free (error);
    g_string_free (message, TRUE);

    return;
  }
}

static gboolean
telco_spawn_instance_handle_breakpoint (TelcoSpawnInstance * self, TelcoBreakpoint * breakpoint, GumDarwinUnifiedThreadState * state)
{
  kern_return_t kr;
  GumAddress pc;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;

  pc = breakpoint->address;

  if (self->breakpoint_phase == TELCO_BREAKPOINT_DETECT_FLAVOR)
  {
    if (self->dyld_flavor == TELCO_DYLD_V4_PLUS)
    {
      if (pc == self->modern_entry_address)
        self->breakpoint_phase = TELCO_BREAKPOINT_SET_LIBDYLD_INITIALIZE_CALLER_BREAKPOINT;
      else
        return telco_spawn_instance_handle_dyld_restart (self);
    }
    else
    {
      memcpy (&self->previous_thread_state, state, sizeof (GumDarwinUnifiedThreadState));

      if (pc == self->modern_entry_address)
        self->breakpoint_phase = TELCO_BREAKPOINT_CF_INITIALIZE;
      else
        self->breakpoint_phase = TELCO_BREAKPOINT_SET_HELPERS;
    }
  }

  if (pc == telco_spawn_instance_get_ret_gadget_address (self))
  {
#ifdef HAVE_I386
    if (self->ret_state == TELCO_RET_FROM_HELPER)
    {
      if (self->cpu_type == GUM_CPU_AMD64)
        state->uts.ts64.__rax = self->fake_error_buf;
      else
        state->uts.ts32.__eax = self->fake_error_buf;
    }
#else
    if (self->cpu_type == GUM_CPU_ARM64)
    {
      GumAddress new_pc;

      new_pc = gum_sign_code_address (__darwin_arm_thread_state64_get_lr (state->ts_64));

      __darwin_arm_thread_state64_set_pc_fptr (state->ts_64, GSIZE_TO_POINTER (new_pc));

      if (self->ret_state == TELCO_RET_FROM_HELPER)
        state->ts_64.__x[0] = self->fake_error_buf;
    }
    else
    {
      state->ts_32.__pc = state->ts_32.__lr;
      if (self->ret_state == TELCO_RET_FROM_HELPER)
        state->ts_32.__r[0] = self->fake_error_buf;
    }
#endif

    self->ret_state = TELCO_RET_FROM_HELPER;

    return TRUE;
  }

  if (telco_spawn_instance_handle_modinit (self, state, pc))
    return TRUE;

next_phase:
  switch (self->breakpoint_phase)
  {
    case TELCO_BREAKPOINT_SET_LIBDYLD_INITIALIZE_CALLER_BREAKPOINT:
    {
      GumAddress frame_pointer = 0;
      guint64 * ret_addr_data;
      GumAddress libsystem_initializer_caller;
      gboolean falls_within_dyld;

#if defined (HAVE_I386)
      frame_pointer = state->uts.ts64.__rbp;
#elif defined (HAVE_ARM64)
      frame_pointer = __darwin_arm_thread_state64_get_fp (state->ts_64);
#endif

      do
      {
        ret_addr_data = (guint64 *) gum_darwin_read (self->task, frame_pointer + 8, 8, NULL);
        libsystem_initializer_caller = *ret_addr_data;
#ifdef HAVE_ARM64
        libsystem_initializer_caller &= G_GUINT64_CONSTANT (0x7fffffffff);
#endif
        g_free (ret_addr_data);

        falls_within_dyld = libsystem_initializer_caller >= self->dyld->base_address &&
            libsystem_initializer_caller < self->dyld->base_address + self->dyld_size;

        if (!falls_within_dyld)
        {
          ret_addr_data = (guint64 *) gum_darwin_read (self->task, frame_pointer, 8, NULL);
          frame_pointer = *ret_addr_data;
          g_free (ret_addr_data);
        }
      }
      while (!falls_within_dyld);

      telco_spawn_instance_set_nth_breakpoint (self, 1, libsystem_initializer_caller, TELCO_BREAKPOINT_REPEAT_ALWAYS);

      self->breakpoint_phase = TELCO_BREAKPOINT_LIBSYSTEM_INITIALIZED;

      return TRUE;
    }

    case TELCO_BREAKPOINT_LIBSYSTEM_INITIALIZED:
      memcpy (&self->previous_thread_state, state, sizeof (GumDarwinUnifiedThreadState));
      self->breakpoint_phase = TELCO_BREAKPOINT_CF_INITIALIZE;
      goto next_phase;

    case TELCO_BREAKPOINT_SET_HELPERS:
      telco_spawn_instance_create_dyld_data (self);

      telco_spawn_instance_call_set_helpers (self, state, self->fake_helpers);

      telco_spawn_instance_set_nth_breakpoint (self, 2, self->ret_gadget, TELCO_BREAKPOINT_REPEAT_ALWAYS);

      self->breakpoint_phase = TELCO_BREAKPOINT_DLOPEN_LIBC;

      return TRUE;

    case TELCO_BREAKPOINT_DLOPEN_LIBC:
      if (telco_spawn_instance_is_libc_initialized (self))
      {
        telco_spawn_instance_unset_helpers (self);
      }
      else
      {
        GHashTableIter iter;
        gpointer strcmp_check;
        guint breakpoint_index;
        gboolean avoid_breakpoint_conflict = self->fake_helpers != 0 && self->dlerror_clear_address == 0;

        g_hash_table_iter_init (&iter, self->do_modinit_strcmp_checks);
        breakpoint_index = 1;
        while (g_hash_table_iter_next (&iter, &strcmp_check, NULL))
        {
          if (avoid_breakpoint_conflict && breakpoint_index == 2)
            breakpoint_index++;

          telco_spawn_instance_set_nth_breakpoint (self, breakpoint_index, GUM_ADDRESS (strcmp_check), TELCO_BREAKPOINT_REPEAT_ALWAYS);
          breakpoint_index++;
        }
      }

      memcpy (state, &self->previous_thread_state, sizeof (GumDarwinUnifiedThreadState));

      telco_spawn_instance_call_dlopen (self, state, self->lib_name, RTLD_GLOBAL | RTLD_LAZY);

      if (self->dlerror_clear_address != 0)
      {
        telco_spawn_instance_set_nth_breakpoint (self, 3, self->dlerror_clear_address, TELCO_BREAKPOINT_REPEAT_ONCE);
        self->breakpoint_phase = TELCO_BREAKPOINT_SKIP_CLEAR;
      }
      else
      {
        self->breakpoint_phase = TELCO_BREAKPOINT_DLOPEN_BOOTSTRAPPER;
      }

      return TRUE;

    case TELCO_BREAKPOINT_SKIP_CLEAR:
#ifdef HAVE_I386
      if (self->cpu_type == GUM_CPU_AMD64)
        state->uts.ts64.__rip = self->ret_gadget;
      else
        state->uts.ts32.__eip = self->ret_gadget;
#else
      if (self->cpu_type == GUM_CPU_ARM64)
        __darwin_arm_thread_state64_set_pc_fptr (state->ts_64, __darwin_arm_thread_state64_get_lr_fptr (state->ts_64));
      else
        state->ts_32.__pc = state->ts_32.__lr;
#endif

      self->breakpoint_phase = TELCO_BREAKPOINT_DLOPEN_BOOTSTRAPPER;

      return TRUE;

    case TELCO_BREAKPOINT_DLOPEN_BOOTSTRAPPER:
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
      if (self->bootstrapper_name != 0)
      {
        telco_spawn_instance_set_libc_initialized (self);
        telco_spawn_instance_unset_nth_breakpoint (self, 1);
        memcpy (state, &self->previous_thread_state, sizeof (GumDarwinUnifiedThreadState));

        telco_spawn_instance_call_dlopen (self, state, self->bootstrapper_name, RTLD_GLOBAL | RTLD_LAZY);

        self->breakpoint_phase = TELCO_BREAKPOINT_CLEANUP;

        return TRUE;
      }
#endif

    case TELCO_BREAKPOINT_CF_INITIALIZE:
      gum_darwin_enumerate_modules (self->task, telco_find_cf_initialize, self);

      if (self->cf_initialize_address != 0)
      {
        memcpy (state, &self->previous_thread_state, sizeof (GumDarwinUnifiedThreadState));

        if (self->dyld_flavor == TELCO_DYLD_V3_MINUS && pc != self->modern_entry_address)
          telco_spawn_instance_unset_nth_breakpoint (self, 1);

        telco_spawn_instance_call_cf_initialize (self, state);

        self->breakpoint_phase = TELCO_BREAKPOINT_CLEANUP;

        return TRUE;
      }

    case TELCO_BREAKPOINT_CLEANUP:
    {
      task_t self_task;
      gsize page_size;
      TelcoExceptionPortSet * previous_ports;
      mach_msg_type_number_t port_index;
      guint i;

      self_task = mach_task_self ();
      page_size = getpagesize ();

      previous_ports = &self->previous_ports;
      for (port_index = 0; port_index != previous_ports->count; port_index++)
      {
        kr = thread_set_exception_ports (self->thread,
            previous_ports->masks[port_index],
            previous_ports->ports[port_index],
            previous_ports->behaviors[port_index],
            previous_ports->flavors[port_index]);
        if (kr != KERN_SUCCESS)
        {
          mach_port_deallocate (self_task, previous_ports->ports[port_index]);
        }
      }
      previous_ports->count = 0;

      kr = telco_set_thread_state (self->thread, state_flavor, &self->previous_thread_state, state_count);
      if (kr != KERN_SUCCESS)
        return FALSE;

      telco_spawn_instance_destroy_dyld_data (self);

      for (i = 0; i != TELCO_MAX_BREAKPOINTS; i++)
        telco_spawn_instance_unset_nth_breakpoint (self, i);

      for (i = 0; i != TELCO_MAX_PAGE_POOL; i++)
      {
        if (self->page_pool[i].scratch_page != 0)
          mach_vm_deallocate (self->task, self->page_pool[i].scratch_page, page_size);
      }

      telco_set_debug_state (self->thread, &self->previous_debug_state, self->cpu_type);

      if (self->info_address != 0)
        telco_spawn_instance_set_libc_initialized (self);

      self->breakpoint_phase = TELCO_BREAKPOINT_DONE;

      _telco_darwin_helper_backend_on_spawn_instance_ready (self->backend, self->pid);

      return FALSE;
    }

    default:
      g_assert_not_reached ();
  }
}

static gboolean
telco_spawn_instance_handle_dyld_restart (TelcoSpawnInstance * self)
{
  gboolean handled = FALSE;
  GumAddress * info_ptr;
  struct dyld_all_image_infos * info = NULL;
  GumDarwinModule * dyld = NULL;

  info_ptr = (GumAddress *) gum_darwin_read (self->task, self->info_ptr_address, sizeof (GumAddress), NULL);
  if (info_ptr == NULL)
    goto beach;

  info = (struct dyld_all_image_infos *) gum_darwin_read (self->task, *info_ptr, sizeof (struct dyld_all_image_infos), NULL);
  if (info == NULL)
    goto beach;

  dyld = gum_darwin_module_new_from_memory ("/usr/lib/dyld", self->task, GUM_ADDRESS (info->dyldImageLoadAddress),
      GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  if (dyld == NULL)
    goto beach;

  self->modern_entry_address = GUM_ADDRESS (info->dyldImageLoadAddress) + (self->modern_entry_address - self->dyld->base_address);

  g_object_unref (self->dyld);
  self->dyld = g_steal_pointer (&dyld);

  telco_spawn_instance_set_nth_breakpoint (self, 0, self->modern_entry_address, TELCO_BREAKPOINT_REPEAT_ALWAYS);

  handled = TRUE;

beach:
  g_clear_object (&dyld);
  g_free (info);
  g_free (info_ptr);

  return handled;
}

static gboolean
telco_spawn_instance_handle_modinit (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, GumAddress pc)
{
  if (self->do_modinit_strcmp_checks == NULL)
    return FALSE;

  if (g_hash_table_contains (self->do_modinit_strcmp_checks, GSIZE_TO_POINTER (pc)))
  {
#ifdef HAVE_I386
    if (self->cpu_type == GUM_CPU_AMD64)
      state->uts.ts64.__rax = 0;
    else
      state->uts.ts32.__eax = 0;
#else
    if (self->cpu_type == GUM_CPU_ARM64)
      state->ts_64.__x[0] = 0;
    else
      state->ts_32.__r[0] = 0;
#endif

    return TRUE;
  }

  return FALSE;
}

static void
telco_spawn_instance_receive_breakpoint_request (TelcoSpawnInstance * self)
{
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  mach_msg_header_t * header = &request->Head;

  mach_msg_destroy (header);

  bzero (request, sizeof (*request));
  header->msgh_size = sizeof (*request);
  header->msgh_local_port = self->server_port;
  mach_msg_receive (header);
}

static void
telco_spawn_instance_send_breakpoint_response (TelcoSpawnInstance * self)
{
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  __Reply__exception_raise_t response;
  mach_msg_header_t * header;
  kern_return_t kr;

  bzero (&response, sizeof (response));
  header = &response.Head;
  header->msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  header->msgh_size = sizeof (response);
  header->msgh_remote_port = request->Head.msgh_remote_port;
  header->msgh_local_port = MACH_PORT_NULL;
  header->msgh_reserved = 0;
  header->msgh_id = request->Head.msgh_id + 100;
  response.NDR = NDR_record;
  response.RetCode = KERN_SUCCESS;
  kr = mach_msg_send (header);
  if (kr == KERN_SUCCESS)
    request->Head.msgh_remote_port = MACH_PORT_NULL;
}

static gboolean
telco_spawn_instance_is_libc_initialized (TelcoSpawnInstance * self)
{
  gboolean initialized;
  GumAddress initialized_address;
  guint8 * yes;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * info_ptr;

      info_ptr = (guint32 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 17;
      g_free (info_ptr);

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * info_ptr;

      info_ptr = (guint64 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 25;
      g_free (info_ptr);

      break;
    }

    default:
      g_assert_not_reached ();
  }

  yes = (guint8 *) gum_darwin_read (self->task, initialized_address, sizeof (yes), NULL);
  initialized = *yes;
  g_free (yes);

  return initialized;
}

static void
telco_spawn_instance_set_libc_initialized (TelcoSpawnInstance * self)
{
  GumAddress initialized_address;
  gboolean write_succeeded;
  guint8 yes = 1;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * info_ptr;

      info_ptr = (guint32 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 17;
      g_free (info_ptr);

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * info_ptr;

      info_ptr = (guint64 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 25;
      g_free (info_ptr);

      break;
    }

    default:
      g_assert_not_reached ();
  }

  write_succeeded = gum_darwin_write (self->task, initialized_address, &yes, 1);
  g_assert (write_succeeded);
}

static kern_return_t
telco_spawn_instance_create_dyld_data (TelcoSpawnInstance * self)
{
  GumPtrauthSupport ptrauth_support;
  GumAddress ret_gadget;
  TelcoSpawnInstanceDyldData data = { "/usr/lib/libSystem.B.dylib", { 0, }, "", { 0, } };
  kern_return_t kr;
  gboolean write_succeeded;

  if (!gum_darwin_query_ptrauth_support (self->task, &ptrauth_support))
    return KERN_FAILURE;

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  gum_darwin_enumerate_modules (self->task, telco_pick_ios_tvos_bootstrapper, &data);
#endif

  ret_gadget = self->ret_gadget;
  if (ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    ret_gadget = gum_sign_code_address (ret_gadget);

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * helpers32 = (guint32 *) &data.helpers[0];

      /* version */
      helpers32[0] = 1;
      /* acquireGlobalDyldLock */
      helpers32[1] = (guint32) ret_gadget;
      /* releaseGlobalDyldLock */
      helpers32[2] = (guint32) ret_gadget;
      /* getThreadBufferFor_dlerror */
      helpers32[3] = (guint32) ret_gadget;

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * helpers64 = (guint64 *) &data.helpers[0];

      /* version */
      helpers64[0] = 1;
      /* acquireGlobalDyldLock */
      helpers64[1] = ret_gadget;
      /* releaseGlobalDyldLock */
      helpers64[2] = ret_gadget;
      /* getThreadBufferFor_dlerror */
      helpers64[3] = ret_gadget;

      break;
    }

    default:
      g_assert_not_reached ();
  }

  kr = mach_vm_allocate (self->task, &self->dyld_data, sizeof (data), VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS)
    return kr;

  write_succeeded = gum_darwin_write (self->task, self->dyld_data, (const guint8 *) &data, sizeof (data));
  if (!write_succeeded)
    return KERN_FAILURE;

  self->fake_helpers = self->dyld_data + offsetof (TelcoSpawnInstanceDyldData, helpers);
  self->lib_name = self->dyld_data + offsetof (TelcoSpawnInstanceDyldData, libc);
  if (data.bootstrapper[0] == '\0')
    self->bootstrapper_name = 0;
  else
    self->bootstrapper_name = self->dyld_data + offsetof (TelcoSpawnInstanceDyldData, bootstrapper);
  self->fake_error_buf = self->dyld_data + offsetof (TelcoSpawnInstanceDyldData, error_buf);

  return KERN_SUCCESS;
}

static void
telco_spawn_instance_destroy_dyld_data (TelcoSpawnInstance * self)
{
  if (self->dyld_data == 0)
    return;

  vm_deallocate (self->task, (vm_address_t) self->dyld_data, sizeof (TelcoSpawnInstanceDyldData));

  self->dyld_data = 0;
}

#if defined (HAVE_IOS) || defined (HAVE_TVOS)

static gboolean
telco_pick_ios_tvos_bootstrapper (const GumModuleDetails * details, gpointer user_data)
{
  TelcoSpawnInstanceDyldData * data = user_data;
  const gchar * candidates[] = {
    "/usr/lib/substitute-inserter.dylib",
    "/usr/lib/pspawn_payload-stg2.dylib"
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (candidates); i++)
  {
    const gchar * bootstrapper = candidates[i];

    if (strcmp (details->path, bootstrapper) == 0)
    {
      strcpy (data->bootstrapper, details->path);
      return FALSE;
    }
  }

  return TRUE;
}

#endif

static void
telco_spawn_instance_unset_helpers (TelcoSpawnInstance * self)
{
  gboolean write_succeeded;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 null_ptr = 0;

      write_succeeded = gum_darwin_write (self->task, self->helpers_ptr_address, (const guint8 *) &null_ptr, sizeof (null_ptr));

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 null_ptr = 0;

      write_succeeded = gum_darwin_write (self->task, self->helpers_ptr_address, (const guint8 *) &null_ptr, sizeof (null_ptr));

      break;
    }

    default:
      g_assert_not_reached ();
  }

  g_assert (write_succeeded);
}

static void
telco_spawn_instance_call_set_helpers (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, mach_vm_address_t helpers)
{
  GumAddress new_pc, current_pc;

  new_pc = gum_sign_code_address (self->register_helpers_address);

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
  {
    gboolean write_succeeded;

    current_pc = state->uts.ts64.__rip;
    state->uts.ts64.__rip = new_pc;
    state->uts.ts64.__rdi = helpers;

    state->uts.ts64.__rsp -= 8;
    write_succeeded = gum_darwin_write (self->task, state->uts.ts64.__rsp, (const guint8 *) &current_pc, sizeof (current_pc));
    g_assert (write_succeeded);
  }
  else
  {
    guint32 temp[2];
    gboolean write_succeeded;

    current_pc = state->uts.ts32.__eip;
    state->uts.ts32.__eip = new_pc;

    temp[0] = current_pc;
    temp[1] = helpers;
    state->uts.ts32.__esp -= 8;
    write_succeeded = gum_darwin_write (self->task, state->uts.ts32.__esp, (const guint8 *) &temp, sizeof (temp));
    g_assert (write_succeeded);
  }
#else
  if (self->cpu_type == GUM_CPU_ARM64)
  {
    GumAddress new_lr;

    new_lr = gum_sign_code_address (__darwin_arm_thread_state64_get_pc (state->ts_64));

    __darwin_arm_thread_state64_set_pc_fptr (state->ts_64, GSIZE_TO_POINTER (new_pc));
    __darwin_arm_thread_state64_set_lr_fptr (state->ts_64, GSIZE_TO_POINTER (new_lr));
    state->ts_64.__x[0] = helpers;
  }
  else
  {
    current_pc = state->ts_32.__pc;
    state->ts_32.__pc = new_pc;
    state->ts_32.__lr = current_pc | 1;
    state->ts_32.__r[0] = helpers;
  }
#endif
}

static void
telco_spawn_instance_call_dlopen (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state, mach_vm_address_t lib_name, int mode)
{
  GumAddress new_pc, current_pc;

  new_pc = gum_sign_code_address (self->dlopen_address);

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
  {
    gboolean write_succeeded;

    current_pc = state->uts.ts64.__rip;
    state->uts.ts64.__rip = new_pc;
    state->uts.ts64.__rdi = lib_name;
    state->uts.ts64.__rsi = mode;
    state->uts.ts64.__rdx = 0;

    state->uts.ts64.__rsp -= 16;
    write_succeeded = gum_darwin_write (self->task, state->uts.ts64.__rsp, (const guint8 *) &current_pc, sizeof (current_pc));
    g_assert (write_succeeded);
  }
  else
  {
    guint32 temp[4];
    gboolean write_succeeded;

    current_pc = state->uts.ts32.__eip;
    state->uts.ts32.__eip = new_pc;

    temp[0] = current_pc;
    temp[1] = lib_name;
    temp[2] = mode;
    temp[3] = 0;
    state->uts.ts32.__esp -= 16;
    write_succeeded = gum_darwin_write (self->task, state->uts.ts32.__esp, (const guint8 *) &temp, sizeof (temp));
    g_assert (write_succeeded);
  }
#else
  if (self->cpu_type == GUM_CPU_ARM64)
  {
    GumAddress new_lr;

    new_lr = gum_sign_code_address (__darwin_arm_thread_state64_get_pc (state->ts_64));

    __darwin_arm_thread_state64_set_pc_fptr (state->ts_64, GSIZE_TO_POINTER (new_pc));
    __darwin_arm_thread_state64_set_lr_fptr (state->ts_64, GSIZE_TO_POINTER (new_lr));
    state->ts_64.__x[0] = lib_name;
    state->ts_64.__x[1] = mode;
    state->ts_64.__x[2] = 0;
  }
  else
  {
    current_pc = state->ts_32.__pc;
    state->ts_32.__pc = new_pc;
    state->ts_32.__lr = current_pc | 1;
    state->ts_32.__r[0] = lib_name;
    state->ts_32.__r[1] = mode;
    state->ts_32.__r[2] = 0;
  }
#endif
}

static gboolean
telco_find_cf_initialize (const GumModuleDetails * details, gpointer user_data)
{
  TelcoSpawnInstance * self = user_data;
  GumDarwinModule * core_foundation;

  if (strcmp (details->path, CORE_FOUNDATION) != 0)
    return TRUE;

  core_foundation = gum_darwin_module_new_from_memory (CORE_FOUNDATION, self->task, details->range->base_address,
      GUM_DARWIN_MODULE_FLAGS_NONE, NULL);

  self->cf_initialize_address = gum_darwin_module_resolve_symbol_address (core_foundation, "___CFInitialize");

  if (self->cf_initialize_address != 0 && self->cpu_type == GUM_CPU_ARM)
    self->cf_initialize_address |= 1;

  g_object_unref (core_foundation);

  return FALSE;
}

static void
telco_spawn_instance_call_cf_initialize (TelcoSpawnInstance * self, GumDarwinUnifiedThreadState * state)
{
  GumAddress new_pc, current_pc;

  new_pc = gum_sign_code_address (self->cf_initialize_address);

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
  {
    gboolean write_succeeded;

    current_pc = state->uts.ts64.__rip;
    state->uts.ts64.__rip = new_pc;

    state->uts.ts64.__rsp -= 16;
    write_succeeded = gum_darwin_write (self->task, state->uts.ts64.__rsp, (const guint8 *) &current_pc, sizeof (current_pc));
    g_assert (write_succeeded);
  }
  else
  {
    guint32 return_address;
    gboolean write_succeeded;

    current_pc = state->uts.ts32.__eip;
    state->uts.ts32.__eip = new_pc;

    return_address = current_pc;
    state->uts.ts32.__esp -= sizeof (return_address);
    write_succeeded = gum_darwin_write (self->task, state->uts.ts32.__esp, (const guint8 *) &return_address, sizeof (return_address));
    g_assert (write_succeeded);
  }
#else
  if (self->cpu_type == GUM_CPU_ARM64)
  {
    GumAddress new_lr;

    new_lr = gum_sign_code_address (__darwin_arm_thread_state64_get_pc (state->ts_64));

    __darwin_arm_thread_state64_set_pc_fptr (state->ts_64, GSIZE_TO_POINTER (new_pc));
    __darwin_arm_thread_state64_set_lr_fptr (state->ts_64, GSIZE_TO_POINTER (new_lr));
  }
  else
  {
    current_pc = state->ts_32.__pc;
    state->ts_32.__pc = new_pc;
    state->ts_32.__lr = current_pc | 1;
  }
#endif
}

static void
telco_spawn_instance_set_nth_breakpoint (TelcoSpawnInstance * self, guint n, GumAddress break_at, TelcoBreakpointRepeat repeat)
{
  g_assert (n < TELCO_MAX_BREAKPOINTS);

  if (self->breakpoints[n].address != 0 && self->breakpoints[n].address != break_at)
    telco_spawn_instance_disable_nth_breakpoint (self, n);

  self->breakpoints[n].address = break_at;
  self->breakpoints[n].repeat = repeat;

  telco_spawn_instance_enable_nth_breakpoint (self, n);
}

static void
telco_spawn_instance_enable_nth_breakpoint (TelcoSpawnInstance * self, guint n)
{
  TelcoBreakpoint * breakpoint;

  g_assert (n < TELCO_MAX_BREAKPOINTS);

  breakpoint = &self->breakpoints[n];

  if (breakpoint->address == 0)
    return;

  if (telco_is_hardware_breakpoint_support_working ())
    telco_set_nth_hardware_breakpoint (&self->breakpoint_debug_state, n, breakpoint->address, self->cpu_type);
  else
    breakpoint->original = telco_spawn_instance_put_software_breakpoint (self, breakpoint->address, n);
}

static void
telco_spawn_instance_unset_nth_breakpoint (TelcoSpawnInstance * self, guint n)
{
  g_assert (n < TELCO_MAX_BREAKPOINTS);

  telco_spawn_instance_disable_nth_breakpoint (self, n);

  self->breakpoints[n].address = 0;
  self->breakpoints[n].repeat = TELCO_BREAKPOINT_REPEAT_NEVER;
}

static void
telco_spawn_instance_disable_nth_breakpoint (TelcoSpawnInstance * self, guint n)
{
  g_assert (n < TELCO_MAX_BREAKPOINTS);

  if (telco_is_hardware_breakpoint_support_working ())
  {
    telco_set_nth_hardware_breakpoint (&self->breakpoint_debug_state, n, 0, self->cpu_type);
  }
  else
  {
    TelcoBreakpoint * breakpoint = &self->breakpoints[n];

    if (breakpoint->address != 0)
      telco_spawn_instance_overwrite_arm64_instruction (self, breakpoint->address, breakpoint->original);
  }
}

static guint32
telco_spawn_instance_put_software_breakpoint (TelcoSpawnInstance * self, GumAddress where, guint index)
{
  guint32 instr_data;

  g_assert (index < TELCO_MAX_BREAKPOINTS);

  instr_data = 0xd4200000 | ((index & 0xffff) << 5);

  return telco_spawn_instance_overwrite_arm64_instruction (self, where, instr_data);
}

static guint32
telco_spawn_instance_overwrite_arm64_instruction (TelcoSpawnInstance * self, GumAddress address, guint32 new_instruction)
{
  guint32 original_instruction;
  gsize page_size;
  GumAddress page_start;
  gsize page_offset;
  GumAddress scratch_page;
  guint i;
  kern_return_t kr;
  guint32 * original_instruction_ptr;
  gboolean write_succeeded;
  GumAddress target_address;
  vm_prot_t cur_protection, max_protection;

  page_size = getpagesize ();

  page_start = address & ~(page_size - 1);
  page_offset = address - page_start;

  scratch_page = 0;

  for (i = 0; i != TELCO_MAX_PAGE_POOL; i++)
  {
    if (self->page_pool[i].page_start == page_start)
    {
      scratch_page = self->page_pool[i].scratch_page;
      break;
    }
  }

  if (scratch_page == 0)
  {
    kr = mach_vm_allocate (self->task, (mach_vm_address_t *) &scratch_page, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
      return 0;

    kr = mach_vm_copy (self->task, page_start, page_size, scratch_page);
    if (kr != KERN_SUCCESS)
      return 0;

    for (i = 0; i != TELCO_MAX_PAGE_POOL; i++)
    {
      if (self->page_pool[i].page_start == 0)
      {
        self->page_pool[i].page_start = page_start;
        self->page_pool[i].scratch_page = scratch_page;
        break;
      }
    }
  }
  else
  {
    kr = mach_vm_protect (self->task, scratch_page, page_size, FALSE, PROT_READ | PROT_WRITE);
    if (kr != KERN_SUCCESS)
      return 0;
  }

  original_instruction_ptr = (guint32 *) gum_darwin_read (self->task, address, 4, NULL);
  original_instruction = *original_instruction_ptr;
  g_free (original_instruction_ptr);

  write_succeeded = gum_darwin_write (self->task, scratch_page + page_offset, (const guint8 *) &new_instruction, 4);
  if (!write_succeeded)
    return 0;

  kr = mach_vm_protect (self->task, scratch_page, page_size, FALSE, PROT_READ | PROT_EXEC);
  if (kr != KERN_SUCCESS)
    return 0;

  target_address = address - page_offset;

  kr = mach_vm_remap (self->task, (mach_vm_address_t *) &target_address, page_size, 0,
      VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self->task, scratch_page, TRUE,
      &cur_protection, &max_protection, VM_INHERIT_COPY);
  if (kr != KERN_SUCCESS)
    return 0;

  return original_instruction;
}

static void
telco_make_pty (int fds[2])
{
  gboolean pipe_opened;
  int i;

  pipe_opened = openpty (&fds[0], &fds[1], NULL, NULL, NULL) != -1;
  g_assert (pipe_opened);

  for (i = 0; i != 2; i++)
  {
    const int fd = fds[i];
    int res;

    res = fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
    g_assert (res == 0);

    res = fcntl (fd, F_SETNOSIGPIPE, TRUE);
    g_assert (res == 0);
  }

  telco_configure_terminal_attributes (fds[0]);
}

static void
telco_configure_terminal_attributes (gint fd)
{
  struct termios tios;

  tcgetattr (fd, &tios);

  tios.c_oflag &= ~ONLCR;
  tios.c_cflag = (tios.c_cflag & CLOCAL) | CS8 | CREAD | HUPCL;
  tios.c_lflag &= ~ECHO;

  tcsetattr (fd, 0, &tios);
}

static TelcoInjectInstance *
telco_inject_instance_new (TelcoDarwinHelperBackend * backend, guint id, guint pid)
{
  TelcoInjectInstance * instance;

  instance = g_slice_new (TelcoInjectInstance);
  instance->id = id;

  instance->pid = pid;
  instance->task = MACH_PORT_NULL;

  instance->payload_address = 0;
  instance->payload_size = 0;
  instance->agent_context = NULL;
  instance->agent_context_size = 0;
  instance->is_loaded = FALSE;
  instance->is_mapped = FALSE;

  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  instance->backend = g_object_ref (backend);

  return instance;
}

static TelcoInjectInstance *
telco_inject_instance_clone (const TelcoInjectInstance * instance, guint id)
{
  TelcoInjectInstance * clone;
  mach_port_t self_task;
  mach_vm_address_t agent_context_address = 0;
  kern_return_t kr;

  clone = g_slice_dup (TelcoInjectInstance, instance);
  clone->id = id;

  clone->task = MACH_PORT_NULL;

  self_task = mach_task_self ();

  kr = mach_vm_allocate (self_task, &agent_context_address, instance->agent_context_size, VM_FLAGS_ANYWHERE);
  g_assert (kr == KERN_SUCCESS);

  clone->agent_context = (TelcoAgentContext *) agent_context_address;
  memcpy (clone->agent_context, instance->agent_context, instance->agent_context_size);

  clone->thread = MACH_PORT_NULL;
  clone->thread_monitor_source = NULL;

  g_object_ref (clone->backend);

  return clone;
}

static void
telco_inject_instance_free (TelcoInjectInstance * instance)
{
  TelcoAgentContext * agent_context = instance->agent_context;
  task_t self_task;
  gboolean can_deallocate_payload;

  self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);

  can_deallocate_payload = !(agent_context != NULL && agent_context->unload_policy != TELCO_UNLOAD_POLICY_IMMEDIATE && instance->is_mapped);
  if (instance->payload_address != 0 &&
      can_deallocate_payload &&
      telco_inject_instance_task_did_not_exec (instance))
  {
    mach_vm_deallocate (instance->task, instance->payload_address, instance->payload_size);

    if (instance->is_loaded)
    {
      _telco_darwin_helper_backend_on_inject_instance_unloaded (instance->backend, instance->id, instance->pid);
    }
  }
  else
  {
    _telco_darwin_helper_backend_on_inject_instance_detached (instance->backend, instance->id, instance->pid);
  }

  if (agent_context != NULL)
    mach_vm_deallocate (self_task, (mach_vm_address_t) agent_context, instance->agent_context_size);

  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);

  g_object_unref (instance->backend);

  g_slice_free (TelcoInjectInstance, instance);
}

static gboolean
telco_inject_instance_task_did_not_exec (TelcoInjectInstance * instance)
{
  gchar * local_cookie, * remote_cookie;
  gboolean shared_memory_still_mapped;

  local_cookie = g_uuid_string_random ();

  strcpy ((gchar *) instance->agent_context, local_cookie);

  remote_cookie = (gchar *) gum_darwin_read (instance->task, instance->remote_agent_context, strlen (local_cookie) + 1, NULL);
  if (remote_cookie != NULL)
  {
    /*
     * This is racy and the only way to avoid this TOCTOU issue is to perform the mach_vm_deallocate() from
     * the remote process. That would however be very tricky to implement, so we mitigate it by delaying
     * cleanup a little.
     *
     * Note that this is not an issue on newer kernels like on iOS 10, where the task port gets invalidated
     * by exec transitions.
     */
    shared_memory_still_mapped = strcmp (remote_cookie, local_cookie) == 0;
  }
  else
  {
    shared_memory_still_mapped = FALSE;
  }

  g_free (remote_cookie);
  g_free (local_cookie);

  return shared_memory_still_mapped;
}

static gboolean
telco_agent_context_init (TelcoAgentContext * self, const TelcoAgentDetails * details, const TelcoInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error)
{
  bzero (self, sizeof (TelcoAgentContext));

  self->unload_policy = TELCO_UNLOAD_POLICY_IMMEDIATE;
  self->task = MACH_PORT_NULL;
  self->mach_thread = MACH_PORT_NULL;
  self->posix_thread = MACH_PORT_NULL;
  self->posix_tid = 0;
  self->constructed = FALSE;
  self->module_handle = NULL;

  if (!telco_agent_context_init_functions (self, resolver, mapper, error))
    return FALSE;

  self->mach_port_allocate_right = MACH_PORT_RIGHT_RECEIVE;

  self->pthread_create_start_routine = payload_base + layout->pthread_code_offset;
  if (details->cpu_type == GUM_CPU_ARM)
    self->pthread_create_start_routine |= 1;
  self->pthread_create_arg = payload_base + layout->data_offset;

  self->message_that_never_arrives = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (TelcoAgentContext, message_that_never_arrives_storage);
  self->message_that_never_arrives_storage.header.msgh_size = sizeof (mach_msg_empty_rcv_t);

  self->dylib_path = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (TelcoAgentContext, dylib_path_storage);
  if (details->dylib_path != NULL)
    strcpy (self->dylib_path_storage, details->dylib_path);
  self->dlopen_mode = RTLD_LAZY;

  self->entrypoint_name = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (TelcoAgentContext, entrypoint_name_storage);
  strcpy (self->entrypoint_name_storage, details->entrypoint_name);

  self->entrypoint_data = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (TelcoAgentContext, entrypoint_data_storage);
  g_assert (strlen (details->entrypoint_data) < sizeof (self->entrypoint_data_storage));
  strcpy (self->entrypoint_data_storage, details->entrypoint_data);

  self->mapped_range = (mapper != NULL)
      ? payload_base + layout->data_offset + G_STRUCT_OFFSET (TelcoAgentContext, mapped_range_storage)
      : 0;
  self->mapped_range_storage.base_address = payload_base;
  self->mapped_range_storage.size = payload_size;

  return TRUE;
}

#define TELCO_AGENT_CONTEXT_RESOLVE(field) \
  G_STMT_START \
  { \
    TELCO_AGENT_CONTEXT_TRY_RESOLVE (field); \
    if (self->field##_impl == 0) \
      goto missing_symbol; \
  } \
  G_STMT_END
#define TELCO_AGENT_CONTEXT_TRY_RESOLVE(field) \
  self->field##_impl = gum_strip_code_address (gum_darwin_module_resolver_find_export_address (resolver, module, G_STRINGIFY (field)))

static gboolean
telco_agent_context_init_functions (TelcoAgentContext * self, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error)
{
  GumDarwinModule * module;

  module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libsystem_kernel.dylib");
  if (module == NULL)
    goto no_libc;
  TELCO_AGENT_CONTEXT_RESOLVE (mach_task_self);
  TELCO_AGENT_CONTEXT_RESOLVE (mach_thread_self);
  TELCO_AGENT_CONTEXT_RESOLVE (mach_port_allocate);
  TELCO_AGENT_CONTEXT_RESOLVE (mach_msg_receive);
  TELCO_AGENT_CONTEXT_RESOLVE (mach_port_destroy);
  TELCO_AGENT_CONTEXT_RESOLVE (thread_terminate);

  module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libsystem_pthread.dylib");
  if (module == NULL)
    goto no_libc;
  TELCO_AGENT_CONTEXT_TRY_RESOLVE (pthread_create_from_mach_thread);
  if (self->pthread_create_from_mach_thread_impl != 0)
    self->pthread_create_impl = self->pthread_create_from_mach_thread_impl;
  else
    TELCO_AGENT_CONTEXT_RESOLVE (pthread_create);
  TELCO_AGENT_CONTEXT_TRY_RESOLVE (pthread_threadid_np);
  TELCO_AGENT_CONTEXT_RESOLVE (pthread_detach);
  TELCO_AGENT_CONTEXT_RESOLVE (pthread_self);

  if (mapper == NULL)
  {
    module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libdyld.dylib");
    if (module == NULL)
      goto no_libc;
    TELCO_AGENT_CONTEXT_RESOLVE (dlopen);
    TELCO_AGENT_CONTEXT_RESOLVE (dlsym);
    TELCO_AGENT_CONTEXT_RESOLVE (dlclose);
  }

  return TRUE;

no_libc:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unable to attach to processes without Apple's libc (for now)");
    goto failure;
  }
missing_symbol:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving functions");
    goto failure;
  }
failure:
  {
    return FALSE;
  }
}

#ifdef HAVE_I386

static void telco_agent_context_emit_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);
static void telco_agent_context_emit_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);

static void
telco_agent_context_emit_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, resolver->cpu_type);
  ctx.mapper = mapper;

  telco_agent_context_emit_mach_stub_body (self, &ctx);
  gum_x86_writer_put_breakpoint (&ctx.cw);

  gum_x86_writer_clear (&ctx.cw);
}

static void
telco_agent_context_emit_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;
  guint locals_size;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, resolver->cpu_type);
  ctx.mapper = mapper;

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_X86_XBP);
  gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_X86_XBP, GUM_X86_XSP);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_X86_XBX);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_X86_XDI);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_X86_XSI);

  locals_size = (ctx.cw.target_cpu == GUM_CPU_IA32) ? 12 : 8;
  gum_x86_writer_put_sub_reg_imm (&ctx.cw, GUM_X86_XSP, locals_size);

  if (ctx.cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx.cw, GUM_X86_XBX, GUM_X86_XBP, 8);
  else
    gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_X86_XBX, GUM_X86_XDI);

  telco_agent_context_emit_pthread_stub_body (self, &ctx);

  gum_x86_writer_put_add_reg_imm (&ctx.cw, GUM_X86_XSP, locals_size);

  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_X86_XSI);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_X86_XDI);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_X86_XBX);
  gum_x86_writer_put_leave (&ctx.cw);
  gum_x86_writer_put_ret (&ctx.cw);

  gum_x86_writer_clear (&ctx.cw);
}

#define EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_X86_##dstreg, GUM_X86_##srcreg)
#define EMIT_LEA(dst, src, offset) \
    gum_x86_writer_put_lea_reg_reg_offset (&ctx->cw, GUM_X86_##dst, GUM_X86_##src, offset)
#define EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_X86_##reg, GUM_X86_XBX, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_LOAD_ADDRESS_OF(reg, field) \
    gum_x86_writer_put_lea_reg_reg_offset (&ctx->cw, GUM_X86_##reg, GUM_X86_XBX, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_STORE(field, reg) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_X86_XBX, G_STRUCT_OFFSET (TelcoAgentContext, field), GUM_X86_##reg)
#define EMIT_CALL(fun, ...) \
    gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_X86_XBX, G_STRUCT_OFFSET (TelcoAgentContext, fun), __VA_ARGS__)

static void
telco_agent_context_emit_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_CALL (mach_task_self_impl, 0);
  EMIT_STORE (task, EAX);

  EMIT_CALL (mach_thread_self_impl, 0);
  EMIT_STORE (mach_thread, EAX);

  gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_X86_XSP, 16);

  EMIT_LOAD (EDI, task);
  EMIT_LOAD (ESI, mach_port_allocate_right);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_X86_XDX, GUM_X86_XSP);
  EMIT_CALL (mach_port_allocate_impl,
      3,
      GUM_ARG_REGISTER, GUM_X86_EDI,
      GUM_ARG_REGISTER, GUM_X86_ESI,
      GUM_ARG_REGISTER, GUM_X86_XDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_X86_EAX, GUM_X86_XSP, 0);
  EMIT_STORE (receive_port, EAX);
  EMIT_LOAD (XDI, message_that_never_arrives);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_X86_XDI, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port), GUM_X86_EAX);

  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_X86_XDI, GUM_X86_XSP);
  EMIT_LOAD (XDX, pthread_create_start_routine);
  EMIT_LOAD (XCX, pthread_create_arg);
  EMIT_CALL (pthread_create_impl,
      4,
      GUM_ARG_REGISTER, GUM_X86_XDI,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      GUM_ARG_REGISTER, GUM_X86_XDX,
      GUM_ARG_REGISTER, GUM_X86_XCX);

  gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_X86_XSP, 16);

  gum_x86_writer_put_label (&ctx->cw, again);

  EMIT_LOAD (XAX, message_that_never_arrives);
  EMIT_CALL (mach_msg_receive_impl,
      1,
      GUM_ARG_REGISTER, GUM_X86_XAX);

  gum_x86_writer_put_jmp_short_label (&ctx->cw, again);
}

static void
telco_agent_context_emit_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  gssize pointer_size, injector_state_offset;
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_CALL (mach_thread_self_impl, 0);
  EMIT_STORE (posix_thread, EAX);

  if (self->pthread_threadid_np_impl != 0)
  {
    EMIT_LOAD_ADDRESS_OF (XSI, posix_tid);
    EMIT_CALL (pthread_threadid_np_impl,
        2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (0),
        GUM_ARG_REGISTER, GUM_X86_XSI);
  }

  EMIT_LOAD (EDI, task);
  EMIT_LOAD (ESI, receive_port);
  EMIT_CALL (mach_port_destroy_impl,
      2,
      GUM_ARG_REGISTER, GUM_X86_EDI,
      GUM_ARG_REGISTER, GUM_X86_ESI);

  EMIT_LOAD (EDI, mach_thread);
  EMIT_CALL (thread_terminate_impl,
      1,
      GUM_ARG_REGISTER, GUM_X86_EDI);

  pointer_size = (ctx->cw.target_cpu == GUM_CPU_IA32) ? 4 : 8;

  injector_state_offset = -(3 + 1) * pointer_size;
  EMIT_LOAD (XDX, mapped_range);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw,
      GUM_X86_XBP, injector_state_offset + G_STRUCT_OFFSET (TelcoDarwinInjectorState, mapped_range),
      GUM_X86_XDX);

  if (ctx->mapper != NULL)
  {
    EMIT_LOAD (EAX, constructed);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_X86_EAX, GUM_X86_EAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_construction, GUM_NO_HINT);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_X86_XAX, gum_darwin_mapper_constructor (ctx->mapper));
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_X86_XAX, 0);
    gum_x86_writer_put_mov_reg_u32 (&ctx->cw, GUM_X86_EAX, TRUE);
    EMIT_STORE (constructed, EAX);

    gum_x86_writer_put_label (&ctx->cw, skip_construction);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_X86_XAX, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_LOAD (XDI, entrypoint_data);
    EMIT_LOAD_ADDRESS_OF (XSI, unload_policy);
    EMIT_LEA (XDX, XBP, injector_state_offset);
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_X86_XAX,
        3,
        GUM_ARG_REGISTER, GUM_X86_XDI,
        GUM_ARG_REGISTER, GUM_X86_XSI,
        GUM_ARG_REGISTER, GUM_X86_XDX);
  }
  else
  {
    EMIT_LOAD (XAX, module_handle);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_dlopen, GUM_NO_HINT);

    EMIT_LOAD (XDI, dylib_path);
    EMIT_LOAD (ESI, dlopen_mode);
    EMIT_CALL (dlopen_impl,
        2,
        GUM_ARG_REGISTER, GUM_X86_XDI,
        GUM_ARG_REGISTER, GUM_X86_ESI);
    EMIT_STORE (module_handle, XAX);

    gum_x86_writer_put_label (&ctx->cw, skip_dlopen);

    EMIT_LOAD (XSI, entrypoint_name);
    EMIT_CALL (dlsym_impl,
        2,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_REGISTER, GUM_X86_XSI);

    EMIT_LOAD (XDI, entrypoint_data);
    EMIT_LOAD_ADDRESS_OF (XSI, unload_policy);
    EMIT_LEA (XDX, XBP, injector_state_offset);
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_X86_XAX,
        3,
        GUM_ARG_REGISTER, GUM_X86_XDI,
        GUM_ARG_REGISTER, GUM_X86_XSI,
        GUM_ARG_REGISTER, GUM_X86_XDX);
  }

  EMIT_LOAD (EAX, unload_policy);
  gum_x86_writer_put_cmp_reg_i32 (&ctx->cw, GUM_X86_EAX, TELCO_UNLOAD_POLICY_IMMEDIATE);
  gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_destruction, GUM_NO_HINT);

  if (ctx->mapper != NULL)
  {
    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_X86_XAX, gum_darwin_mapper_destructor (ctx->mapper));
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_X86_XAX, 0);
  }
  else
  {
    EMIT_LOAD (XDI, module_handle);
    EMIT_CALL (dlclose_impl,
        1,
        GUM_ARG_REGISTER, GUM_X86_XDI);
  }

  gum_x86_writer_put_label (&ctx->cw, skip_destruction);

  EMIT_LOAD (EAX, unload_policy);
  gum_x86_writer_put_cmp_reg_i32 (&ctx->cw, GUM_X86_EAX, TELCO_UNLOAD_POLICY_DEFERRED);
  gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JE, skip_detach, GUM_NO_HINT);

  EMIT_CALL (pthread_self_impl, 0);

  EMIT_CALL (pthread_detach_impl,
      1,
      GUM_ARG_REGISTER, GUM_X86_XAX);

  gum_x86_writer_put_label (&ctx->cw, skip_detach);
}

#else

/*
 * ARM 32- and 64-bit
 */

static void telco_agent_context_emit_arm_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);
static void telco_agent_context_emit_arm_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);
static void telco_agent_context_emit_arm_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);
static void telco_agent_context_emit_arm_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);
static void telco_agent_context_emit_arm_load_reg_with_ctx_value (arm_reg reg, guint field_offset, GumThumbWriter * tw);
static void telco_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, arm_reg reg, GumThumbWriter * tw);

static void telco_agent_context_emit_arm64_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);
static void telco_agent_context_emit_arm64_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper);
static void telco_agent_context_emit_arm64_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);
static void telco_agent_context_emit_arm64_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx);

static void
telco_agent_context_emit_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  if (resolver->cpu_type == GUM_CPU_ARM)
    telco_agent_context_emit_arm_mach_stub_code (self, code, resolver, mapper);
  else
    telco_agent_context_emit_arm64_mach_stub_code (self, code, resolver, mapper);
}

static void
telco_agent_context_emit_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  if (resolver->cpu_type == GUM_CPU_ARM)
    telco_agent_context_emit_arm_pthread_stub_code (self, code, resolver, mapper);
  else
    telco_agent_context_emit_arm64_pthread_stub_code (self, code, resolver, mapper);
}


/*
 * ARM 32-bit
 */

static void
telco_agent_context_emit_arm_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  telco_agent_context_emit_arm_mach_stub_body (self, &ctx);

  gum_thumb_writer_clear (&ctx.tw);
}

static void
telco_agent_context_emit_arm_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  gum_thumb_writer_put_push_regs (&ctx.tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
  gum_thumb_writer_put_mov_reg_reg (&ctx.tw, ARM_REG_R7, ARM_REG_R0);
  telco_agent_context_emit_arm_pthread_stub_body (self, &ctx);
  gum_thumb_writer_put_pop_regs (&ctx.tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_clear (&ctx.tw);
}

#define EMIT_ARM_LOAD(reg, field) \
    telco_agent_context_emit_arm_load_reg_with_ctx_value (ARM_REG_##reg, G_STRUCT_OFFSET (TelcoAgentContext, field), &ctx->tw)
#define EMIT_ARM_LOAD_ADDRESS_OF(reg, field) \
    gum_thumb_writer_put_add_reg_reg_imm (&ctx->tw, ARM_REG_##reg, ARM_REG_R7, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_ARM_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, ARM_REG_##reg, val)
#define EMIT_ARM_STORE(field, reg) \
    telco_agent_context_emit_arm_store_reg_in_ctx_value (G_STRUCT_OFFSET (TelcoAgentContext, field), ARM_REG_##reg, &ctx->tw)
#define EMIT_ARM_MOVE(dstreg, srcreg) \
    gum_thumb_writer_put_mov_reg_reg (&ctx->tw, ARM_REG_##dstreg, ARM_REG_##srcreg)
#define EMIT_ARM_CALL(reg) \
    gum_thumb_writer_put_blx_reg (&ctx->tw, ARM_REG_##reg)
#define EMIT_ARM_STACK_ADJUSTMENT(delta) \
    gum_thumb_writer_put_sub_reg_imm (&ctx->tw, ARM_REG_SP, delta * 4)

static void
telco_agent_context_emit_arm_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_ARM_LOAD (R4, mach_task_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (task, R0);

  EMIT_ARM_LOAD (R4, mach_thread_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (mach_thread, R0);

  EMIT_ARM_LOAD (R0, task);
  EMIT_ARM_LOAD (R1, mach_port_allocate_right);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_MOVE (R2, SP);
  EMIT_ARM_LOAD (R4, mach_port_allocate_impl);
  EMIT_ARM_CALL (R4);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_STORE (receive_port, R0);
  EMIT_ARM_LOAD (R1, message_that_never_arrives);
  gum_thumb_writer_put_str_reg_reg_offset (&ctx->tw, ARM_REG_R0, ARM_REG_R1, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port));

  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_MOVE (R0, SP);
  EMIT_ARM_LOAD_U32 (R1, 0);
  EMIT_ARM_LOAD (R2, pthread_create_start_routine);
  EMIT_ARM_LOAD (R3, pthread_create_arg);
  EMIT_ARM_LOAD (R4, pthread_create_impl);
  EMIT_ARM_CALL (R4);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, ARM_REG_R0);

  gum_thumb_writer_put_label (&ctx->tw, again);

  EMIT_ARM_LOAD (R0, message_that_never_arrives);
  EMIT_ARM_LOAD (R4, mach_msg_receive_impl);
  EMIT_ARM_CALL (R4);

  gum_thumb_writer_put_b_label (&ctx->tw, again);
}

static void
telco_agent_context_emit_arm_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_ARM_LOAD (R4, mach_thread_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (posix_thread, R0);

  if (self->pthread_threadid_np_impl != 0)
  {
    EMIT_ARM_LOAD_U32 (R0, 0);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, posix_tid);
    EMIT_ARM_LOAD (R4, pthread_threadid_np_impl);
    EMIT_ARM_CALL (R4);
  }

  EMIT_ARM_LOAD (R0, task);
  EMIT_ARM_LOAD (R1, receive_port);
  EMIT_ARM_LOAD (R4, mach_port_destroy_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD (R0, mach_thread);
  EMIT_ARM_LOAD (R4, thread_terminate_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_STACK_ADJUSTMENT (3);
  EMIT_ARM_LOAD (R0, mapped_range);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0); /* DarwinInjectorState */

  if (ctx->mapper != NULL)
  {
    EMIT_ARM_LOAD (R0, constructed);
    gum_thumb_writer_put_cbnz_reg_label (&ctx->tw, ARM_REG_R0, skip_construction);

    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM_CALL (R4);
    gum_thumb_writer_put_mov_reg_u8 (&ctx->tw, ARM_REG_R0, TRUE);
    EMIT_ARM_STORE (constructed, R0);

    gum_thumb_writer_put_label (&ctx->tw, skip_construction);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, unload_policy);
    EMIT_ARM_MOVE (R2, SP);
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM_CALL (R4);
  }
  else
  {
    EMIT_ARM_LOAD (R5, module_handle);
    gum_thumb_writer_put_cbnz_reg_label (&ctx->tw, ARM_REG_R5, skip_dlopen);

    EMIT_ARM_LOAD (R0, dylib_path);
    EMIT_ARM_LOAD (R1, dlopen_mode);
    EMIT_ARM_LOAD (R4, dlopen_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R5, R0);
    EMIT_ARM_STORE (module_handle, R5);

    gum_thumb_writer_put_label (&ctx->tw, skip_dlopen);

    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R1, entrypoint_name);
    EMIT_ARM_LOAD (R4, dlsym_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R4, R0);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, unload_policy);
    EMIT_ARM_MOVE (R2, SP);
    EMIT_ARM_CALL (R4);
  }

  EMIT_ARM_STACK_ADJUSTMENT (-4);

  EMIT_ARM_LOAD (R0, unload_policy);
  gum_thumb_writer_put_cmp_reg_imm (&ctx->tw, ARM_REG_R0, TELCO_UNLOAD_POLICY_IMMEDIATE);
  gum_thumb_writer_put_bne_label (&ctx->tw, skip_destruction);

  if (ctx->mapper != NULL)
  {
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_destructor (ctx->mapper));
    EMIT_ARM_CALL (R4);
  }
  else
  {
    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R4, dlclose_impl);
    EMIT_ARM_CALL (R4);
  }

  gum_thumb_writer_put_label (&ctx->tw, skip_destruction);

  EMIT_ARM_LOAD (R0, unload_policy);
  gum_thumb_writer_put_cmp_reg_imm (&ctx->tw, ARM_REG_R0, TELCO_UNLOAD_POLICY_DEFERRED);
  gum_thumb_writer_put_beq_label (&ctx->tw, skip_detach);

  EMIT_ARM_LOAD (R4, pthread_self_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD (R4, pthread_detach_impl);
  EMIT_ARM_CALL (R4);

  gum_thumb_writer_put_label (&ctx->tw, skip_detach);
}

static void
telco_agent_context_emit_arm_load_reg_with_ctx_value (arm_reg reg, guint field_offset, GumThumbWriter * tw)
{
  arm_reg tmp_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, reg, ARM_REG_R7, tmp_reg);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}

static void
telco_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, arm_reg reg, GumThumbWriter * tw)
{
  arm_reg tmp_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, tmp_reg, ARM_REG_R7, tmp_reg);
  gum_thumb_writer_put_str_reg_reg (tw, reg, tmp_reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}


/*
 * ARM 64-bit
 */

static void
telco_agent_context_emit_arm64_mach_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  ctx.aw.ptrauth_support = resolver->ptrauth_support;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X21, ARM64_REG_X22);
  telco_agent_context_emit_arm64_mach_stub_body (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);

  gum_arm64_writer_clear (&ctx.aw);
}

static void
telco_agent_context_emit_arm64_pthread_stub_code (TelcoAgentContext * self, guint8 * code, GumDarwinModuleResolver * resolver,
    GumDarwinMapper * mapper)
{
  TelcoAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  ctx.aw.ptrauth_support = resolver->ptrauth_support;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_X20, ARM64_REG_X0);
  telco_agent_context_emit_arm64_pthread_stub_body (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);
  gum_arm64_writer_clear (&ctx.aw);
}

#define EMIT_ARM64_LOAD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_ARM64_LOAD_ADDRESS_OF(reg, field) \
    gum_arm64_writer_put_add_reg_reg_imm (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_ARM64_LOAD_U64(reg, val) \
    gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_##reg, val)
#define EMIT_ARM64_STORE(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (TelcoAgentContext, field))
#define EMIT_ARM64_MOVE(dstreg, srcreg) \
    gum_arm64_writer_put_mov_reg_reg (&ctx->aw, ARM64_REG_##dstreg, ARM64_REG_##srcreg)
#define EMIT_ARM64_CALL(reg) \
    gum_arm64_writer_put_blr_reg_no_auth (&ctx->aw, ARM64_REG_##reg)

static void
telco_agent_context_emit_arm64_mach_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_ARM64_LOAD (X8, mach_task_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (task, W0);

  EMIT_ARM64_LOAD (X8, mach_thread_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (mach_thread, W0);

  EMIT_ARM64_LOAD (W0, task);
  EMIT_ARM64_LOAD (W1, mach_port_allocate_right);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_MOVE (X2, SP);
  EMIT_ARM64_LOAD (X8, mach_port_allocate_impl);
  EMIT_ARM64_CALL (X8);
  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_STORE (receive_port, W0);
  EMIT_ARM64_LOAD (X1, message_that_never_arrives);
  gum_arm64_writer_put_str_reg_reg_offset (&ctx->aw, ARM64_REG_W0, ARM64_REG_X1, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port));

  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_MOVE (X0, SP);

  EMIT_ARM64_LOAD_U64 (X1, 0);

  EMIT_ARM64_LOAD (X2, pthread_create_start_routine);
  if (ctx->aw.ptrauth_support == GUM_PTRAUTH_SUPPORTED)
  {
    const guint32 paciza_x2 = 0xdac123e2;
    gum_arm64_writer_put_instruction (&ctx->aw, paciza_x2);
  }

  EMIT_ARM64_LOAD (X3, pthread_create_arg);

  EMIT_ARM64_LOAD (X8, pthread_create_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_label (&ctx->aw, again);

  EMIT_ARM64_LOAD (X0, message_that_never_arrives);
  EMIT_ARM64_LOAD (X8, mach_msg_receive_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_b_label (&ctx->aw, again);
}

static void
telco_agent_context_emit_arm64_pthread_stub_body (TelcoAgentContext * self, TelcoAgentEmitContext * ctx)
{
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_ARM64_LOAD (X8, mach_thread_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (posix_thread, W0);

  if (self->pthread_threadid_np_impl != 0)
  {
    EMIT_ARM64_LOAD_U64 (X0, 0);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, posix_tid);
    EMIT_ARM64_LOAD (X8, pthread_threadid_np_impl);
    EMIT_ARM64_CALL (X8);
  }

  EMIT_ARM64_LOAD (W0, task);
  EMIT_ARM64_LOAD (W1, receive_port);
  EMIT_ARM64_LOAD (X8, mach_port_destroy_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (W0, mach_thread);
  EMIT_ARM64_LOAD (X8, thread_terminate_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (X0, mapped_range);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1); /* DarwinInjectorState */

  if (ctx->mapper != NULL)
  {
    EMIT_ARM64_LOAD (W0, constructed);
    gum_arm64_writer_put_cbnz_reg_label (&ctx->aw, ARM64_REG_W0, skip_construction);

    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8,
        gum_strip_code_address (gum_darwin_mapper_constructor (ctx->mapper)));
    EMIT_ARM64_CALL (X8);
    gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, TRUE);
    EMIT_ARM64_STORE (constructed, W1);

    gum_arm64_writer_put_label (&ctx->aw, skip_construction);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, unload_policy);
    EMIT_ARM64_MOVE (X2, SP);
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8,
        gum_strip_code_address (gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage)));
    EMIT_ARM64_CALL (X8);
  }
  else
  {
    EMIT_ARM64_LOAD (X19, module_handle);
    gum_arm64_writer_put_cbnz_reg_label (&ctx->aw, ARM64_REG_X19, skip_dlopen);

    EMIT_ARM64_LOAD (X0, dylib_path);
    EMIT_ARM64_LOAD (X1, dlopen_mode);
    EMIT_ARM64_LOAD (X8, dlopen_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X19, X0);
    EMIT_ARM64_STORE (module_handle, X19);

    gum_arm64_writer_put_label (&ctx->aw, skip_dlopen);

    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X1, entrypoint_name);
    EMIT_ARM64_LOAD (X8, dlsym_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X8, X0);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, unload_policy);
    EMIT_ARM64_MOVE (X2, SP);
    EMIT_ARM64_CALL (X8);
  }

  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);

  EMIT_ARM64_LOAD (W0, unload_policy);
  gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, TELCO_UNLOAD_POLICY_IMMEDIATE);
  gum_arm64_writer_put_cmp_reg_reg (&ctx->aw, ARM64_REG_W0, ARM64_REG_W1);
  gum_arm64_writer_put_b_cond_label (&ctx->aw, ARM64_CC_NE, skip_destruction);

  if (ctx->mapper != NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8,
        gum_strip_code_address (gum_darwin_mapper_destructor (ctx->mapper)));
    EMIT_ARM64_CALL (X8);
  }
  else
  {
    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, dlclose_impl);
    EMIT_ARM64_CALL (X8);
  }

  gum_arm64_writer_put_label (&ctx->aw, skip_destruction);

  EMIT_ARM64_LOAD (W0, unload_policy);
  gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, TELCO_UNLOAD_POLICY_DEFERRED);
  gum_arm64_writer_put_cmp_reg_reg (&ctx->aw, ARM64_REG_W0, ARM64_REG_W1);
  gum_arm64_writer_put_b_cond_label (&ctx->aw, ARM64_CC_EQ, skip_detach);

  EMIT_ARM64_LOAD (X8, pthread_self_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (X8, pthread_detach_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_label (&ctx->aw, skip_detach);
}

#endif

static mach_port_t
telco_obtain_thread_port_for_thread_id (mach_port_t task, uint64_t thread_id)
{
  mach_port_t result = MACH_PORT_NULL;
  kern_return_t kr;
  thread_act_array_t threads;
  mach_msg_type_number_t thread_count;
  mach_port_t self_task;
  int i;

  kr = task_threads (task, &threads, &thread_count);
  if (kr != KERN_SUCCESS)
    return MACH_PORT_NULL;

  self_task = mach_task_self ();

  /* Walk backwards as younger threads typically end up towards the end... */
  for (i = thread_count - 1; i >= 0; i--)
  {
    thread_act_t thread = threads[i];
    thread_identifier_info_data_t info;
    mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;

    if (result == MACH_PORT_NULL &&
        thread_info (thread, THREAD_IDENTIFIER_INFO, (thread_info_t) &info, &info_count) == KERN_SUCCESS &&
        info.thread_id == thread_id)
    {
      result = thread;
    }
    else
    {
      mach_port_deallocate (self_task, thread);
    }
  }

  vm_deallocate (self_task, (vm_address_t) threads, thread_count * sizeof (thread_t));

  return result;
}

static kern_return_t
telco_get_thread_state (mach_port_t thread, thread_state_flavor_t flavor, gpointer state, mach_msg_type_number_t * count)
{
  kern_return_t kr;

  kr = thread_get_state (thread, flavor, state, count);
  if (kr == KERN_SUCCESS)
    kr = telco_convert_thread_state_inplace (thread, TELCO_CONVERT_THREAD_STATE_IN, flavor, state, count);

  return kr;
}

static kern_return_t
telco_set_thread_state (mach_port_t thread, thread_state_flavor_t flavor, gconstpointer state, mach_msg_type_number_t count)
{
  kern_return_t kr;
  thread_state_t remote_state;

  remote_state = g_alloca (count * sizeof (integer_t));

  kr = telco_convert_thread_state (thread, TELCO_CONVERT_THREAD_STATE_OUT, flavor, state, count, remote_state, &count);
  if (kr == KERN_SUCCESS)
    kr = thread_set_state (thread, flavor, remote_state, count);

  return kr;
}

static kern_return_t
telco_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type)
{
  thread_state_flavor_t flavor;
  mach_msg_type_number_t count;

#ifdef HAVE_I386
  flavor = x86_DEBUG_STATE;
  count = x86_DEBUG_STATE_COUNT;
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    flavor = ARM_DEBUG_STATE64;
    count = ARM_DEBUG_STATE64_COUNT;
  }
  else
  {
    flavor = ARM_DEBUG_STATE;
    count = ARM_DEBUG_STATE32_COUNT;
  }
#endif

  return telco_get_thread_state (thread, flavor, state, &count);
}

static kern_return_t
telco_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type)
{
  thread_state_flavor_t flavor;
  mach_msg_type_number_t count;

#ifdef HAVE_I386
  flavor = x86_DEBUG_STATE;
  count = x86_DEBUG_STATE_COUNT;
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    flavor = ARM_DEBUG_STATE64;
    count = ARM_DEBUG_STATE64_COUNT;
  }
  else
  {
    flavor = ARM_DEBUG_STATE32;
    count = ARM_DEBUG_STATE32_COUNT;
  }
#endif

  return telco_set_thread_state (thread, flavor, state, count);
}

static kern_return_t
telco_convert_thread_state_inplace (mach_port_t thread, TelcoConvertThreadStateDirection direction, thread_state_flavor_t flavor,
    gpointer state, mach_msg_type_number_t * count)
{
  return telco_convert_thread_state (thread, direction, flavor, state, *count, state, count);
}

static kern_return_t
telco_convert_thread_state (mach_port_t thread, TelcoConvertThreadStateDirection direction, thread_state_flavor_t flavor,
    gconstpointer in_state, mach_msg_type_number_t in_state_count,
    gpointer out_state, mach_msg_type_number_t * out_state_count)
{
  static gboolean initialized = FALSE;
  static kern_return_t (* convert) (thread_act_t thread, TelcoConvertThreadStateDirection direction, thread_state_flavor_t flavor,
      thread_state_t in_state, mach_msg_type_number_t in_state_count,
      thread_state_t out_state, mach_msg_type_number_t * out_state_count);

  if (!initialized)
  {
    void * module;

    module = dlopen ("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (module != NULL);

    convert = dlsym (module, "thread_convert_thread_state");

    dlclose (module);

    initialized = TRUE;
  }

  if (convert == NULL)
    goto fallback;

  return convert (thread, direction, flavor, (thread_state_t) in_state, in_state_count, out_state, out_state_count);

fallback:
  {
    const mach_msg_type_number_t n = MIN (in_state_count, *out_state_count);

    if (out_state != in_state)
      memmove (out_state, in_state, n * sizeof (integer_t));

    *out_state_count = n;

    return KERN_SUCCESS;
  }
}

static void
telco_set_nth_hardware_breakpoint (gpointer state, guint n, GumAddress break_at, GumCpuType cpu_type)
{
#ifdef HAVE_I386
  x86_debug_state_t * s = state;

  if (cpu_type == GUM_CPU_AMD64)
  {
    x86_debug_state64_t * ds = &s->uds.ds64;

    ((guint64 *) &ds->__dr0)[n] = break_at;
    if (break_at != 0)
      ds->__dr7 |= 1 << (n * 2);
    else
      ds->__dr7 &= ~(1 << (n * 2));
  }
  else
  {
    x86_debug_state32_t * ds = &s->uds.ds32;

    ((guint32 *) &ds->__dr0)[n] = break_at;
    if (break_at != 0)
      ds->__dr7 |= 1 << (n * 2);
    else
      ds->__dr7 &= ~(1 << (n * 2));
  }
#else
# define TELCO_S_USER ((uint32_t) (2u << 1))
# define TELCO_BAS_ANY ((uint32_t) 15u)
# define TELCO_BAS_THUMB ((uint32_t) 12u)
# define TELCO_BCR_ENABLE ((uint32_t) 1u)

  if (cpu_type == GUM_CPU_ARM64)
  {
    arm_debug_state64_t * s = state;

    s->__bvr[n] = break_at;
    if (break_at != 0)
      s->__bcr[n] = (TELCO_BAS_ANY << 5) | TELCO_S_USER | TELCO_BCR_ENABLE;
    else
      s->__bcr[n] = 0;
  }
  else
  {
    arm_debug_state_t * s = state;
    uint32_t bas = (break_at & 1) ? TELCO_BAS_THUMB : TELCO_BAS_ANY;

    s->__bvr[n] = break_at;
    if (break_at != 0)
      s->__bcr[n] = (bas << 5) | TELCO_S_USER | TELCO_BCR_ENABLE;
    else
      s->__bcr[n] = 0;
  }
#endif
}

static void
telco_set_hardware_single_step (gpointer debug_state, GumDarwinUnifiedThreadState * thread_state, gboolean enabled, GumCpuType cpu_type)
{
#ifdef HAVE_I386
# define TELCO_SINGLE_STEP_ENABLED 0x0100

  if (cpu_type == GUM_CPU_AMD64)
  {
    x86_thread_state64_t * state = (x86_thread_state64_t *) &thread_state->uts;

    if (enabled)
      state->__rflags |= TELCO_SINGLE_STEP_ENABLED;
    else
      state->__rflags &= ~TELCO_SINGLE_STEP_ENABLED;
  }
  else
  {
    x86_thread_state32_t * state = (x86_thread_state32_t *) &thread_state->uts;

    if (enabled)
      state->__eflags |= TELCO_SINGLE_STEP_ENABLED;
    else
      state->__eflags &= ~TELCO_SINGLE_STEP_ENABLED;
  }
#else
# define TELCO_SINGLE_STEP_ENABLED ((uint32_t) 1u)

  if (cpu_type == GUM_CPU_ARM64)
  {
    arm_debug_state64_t * s = debug_state;

    if (enabled)
      s->__mdscr_el1 |= TELCO_SINGLE_STEP_ENABLED;
    else
      s->__mdscr_el1 = 0;
  }
  else
  {
    arm_debug_state32_t * s = debug_state;

    if (enabled)
      s->__mdscr_el1 |= TELCO_SINGLE_STEP_ENABLED;
    else
      s->__mdscr_el1 = 0;
  }
#endif
}

static gboolean
telco_is_hardware_breakpoint_support_working (void)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    char buf[256];
    size_t size;
    int res;
    float version;
    gboolean buggy_kernel;

    size = sizeof (buf);
    res = sysctlbyname ("kern.osrelease", buf, &size, NULL, 0);
    g_assert (res == 0);

    version = atof (buf);
    buggy_kernel = version >= 17.5f && version <= 18.0f;

    size = sizeof (buf);
    res = sysctlbyname ("kern.version", buf, &size, NULL, 0);
    g_assert (res == 0);

    if (strnstr (buf, "4903.202.2~1", size) != NULL)
      buggy_kernel = FALSE;

    g_once_init_leave (&cached_result, !buggy_kernel + 1);
  }

  return cached_result - 1;
#else
  return TRUE;
#endif
}

static GumAddress
telco_find_run_initializers_call (mach_port_t task, GumCpuType cpu_type, GumAddress start)
{
  GumAddress match = 0;
  const size_t max_size = 2048;
  uint64_t address = start & ~G_GUINT64_CONSTANT (1);
  csh capstone;
  cs_err err;
  gpointer chunk;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;

  capstone = telco_create_capstone (cpu_type, start);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  chunk = gum_darwin_read (task, address, max_size, NULL);

  insn = cs_malloc (capstone);
  code = chunk;
  size = max_size;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_MOV)
        {
          const cs_x86_op * src = &insn->detail->x86.operands[1];
          if (src->type == X86_OP_MEM && src->mem.base != X86_REG_EBP && src->mem.disp == 0x18)
          {
            match = insn->address;
            break;
          }
        }
      }
      break;

    case GUM_CPU_AMD64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_CALL)
        {
          const cs_x86_op * op = &insn->detail->x86.operands[0];
          if (op->type == X86_OP_MEM && op->mem.disp == 0x28)
          {
            match = insn->address;
            break;
          }
        }
      }
      break;

    case GUM_CPU_ARM64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM64_INS_LDR && insn->detail->arm64.operands[1].mem.disp == 0x28)
        {
          match = insn->address;
          break;
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }

  cs_free (insn, 1);
  g_free (chunk);
  cs_close (&capstone);

  return match;
}

static GHashTable *
telco_find_modinit_strcmp_checks (mach_port_t task, GumDarwinModule * dyld)
{
  GHashTable * checks;
  GumAddress modinit_start, modinit_end, dyld_strcmp;
  uint64_t address;
  size_t size;
  csh capstone;
  cs_err err;
  gpointer chunk;
  cs_insn * insn;
  const uint8_t * code;

  modinit_start = gum_darwin_module_resolve_symbol_address (dyld, "__ZN16ImageLoaderMachO18doModInitFunctionsERKN11ImageLoader11LinkContextE");
  modinit_end = gum_darwin_module_resolve_symbol_address (dyld, "__ZN16ImageLoaderMachO16doGetDOFSectionsERKN11ImageLoader11LinkContextERNSt3__16vectorINS0_7DOFInfoENS4_9allocatorIS6_EEEE");
  dyld_strcmp = gum_darwin_module_resolve_symbol_address (dyld, "_strcmp");
  if (modinit_start == 0 || modinit_end == 0 || modinit_end <= modinit_start || dyld_strcmp == 0)
    return NULL;
  address = modinit_start & ~G_GUINT64_CONSTANT (1);
  size = modinit_end - modinit_start;

  capstone = telco_create_capstone (dyld->cpu_type, modinit_start);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  chunk = gum_darwin_read (task, address, size, NULL);

  insn = cs_malloc (capstone);
  code = chunk;

  checks = g_hash_table_new (NULL, NULL);

  switch (dyld->cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_CALL)
        {
          const cs_x86_op * op = &insn->detail->x86.operands[0];

          if (op->type == X86_OP_IMM && op->imm == dyld_strcmp)
          {
            g_hash_table_add (checks, GSIZE_TO_POINTER (insn->address + insn->size));
          }
        }
      }
      break;

    case GUM_CPU_ARM:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM_INS_BLX)
        {
          const cs_arm_op * op = &insn->detail->arm.operands[0];

          if (op->type == ARM_OP_IMM && op->imm == dyld_strcmp)
          {
            g_hash_table_add (checks, GSIZE_TO_POINTER (insn->address + insn->size));
          }
        }
      }
      break;

    case GUM_CPU_ARM64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM64_INS_BL && insn->detail->arm64.operands[0].imm == dyld_strcmp)
        {
          g_hash_table_add (checks, GSIZE_TO_POINTER (insn->address + insn->size));
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }

  switch (g_hash_table_size (checks))
  {
    case 1:
    case 2:
      break;
    default:
      g_hash_table_unref (checks);
      checks = NULL;
  }

  cs_free (insn, 1);
  g_free (chunk);
  cs_close (&capstone);

  return checks;
}

static GumAddress
telco_find_function_end (mach_port_t task, GumCpuType cpu_type, GumAddress start, gsize max_size)
{
  GumAddress match = 0;
  uint64_t address = start & ~G_GUINT64_CONSTANT (1);
  csh capstone;
  cs_err err;
  gpointer chunk;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;

  capstone = telco_create_capstone (cpu_type, start);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  chunk = gum_darwin_read (task, address, max_size, NULL);

  insn = cs_malloc (capstone);
  code = chunk;
  size = max_size;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_RET ||
            insn->id == X86_INS_RETF ||
            insn->id == X86_INS_RETFQ)
        {
          match = insn->address;
          break;
        }
      }
      break;

    case GUM_CPU_ARM:
    {
      int i, pop_lr = -1;

      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM_INS_PUSH &&
            insn->address == (start & ~1))
        {
          for (i = 0; i != insn->detail->arm.op_count; i++)
          {
            if (insn->detail->arm.operands[i].reg == ARM_REG_LR)
            {
              pop_lr = i;
              break;
            }
          }
        }

        if ((insn->id == ARM_INS_BX || insn->id == ARM_INS_BXJ) &&
            insn->detail->arm.operands[0].type == ARM_OP_REG &&
            insn->detail->arm.operands[0].reg == ARM_REG_LR)
        {
          match = insn->address;
          break;
        }

        if (insn->id == ARM_INS_POP &&
            pop_lr >= 0 &&
            pop_lr < insn->detail->arm.op_count)
        {
          if (insn->detail->arm.operands[pop_lr].reg == ARM_REG_PC)
          {
            match = insn->address;
            break;
          }
        }
      }

      break;
    }

    case GUM_CPU_ARM64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM64_INS_RET)
        {
          match = insn->address;
          break;
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }

  cs_free (insn, 1);
  g_free (chunk);
  cs_close (&capstone);

  return match;
}

static csh
telco_create_capstone (GumCpuType cpu_type, GumAddress start)
{
  csh capstone;
  cs_err err;

  switch (cpu_type)
  {
#ifdef HAVE_I386
    case GUM_CPU_IA32:
      cs_arch_register_x86 ();
      err = cs_open (CS_ARCH_X86, CS_MODE_32, &capstone);
      break;

    case GUM_CPU_AMD64:
      cs_arch_register_x86 ();
      err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
      break;
#endif

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
    case GUM_CPU_ARM:
      cs_arch_register_arm ();
      if (start & 1)
        err = cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
      else
        err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
      break;
#endif

#ifdef HAVE_ARM64
    case GUM_CPU_ARM64:
      cs_arch_register_arm64 ();
      err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
      break;
#endif

    default:
      g_assert_not_reached ();
  }

  g_assert (err == CS_ERR_OK);

  return capstone;
}

static gboolean
telco_parse_aslr_option (GVariant * value, TelcoAslr * aslr, GError ** error)
{
  const gchar * str;

  if (!g_variant_is_of_type (value, G_VARIANT_TYPE_STRING))
    goto invalid_type;
  str = g_variant_get_string (value, NULL);

  if (strcmp (str, "auto") == 0)
    *aslr = TELCO_ASLR_AUTO;
  else if (strcmp (str, "disable") == 0)
    *aslr = TELCO_ASLR_DISABLE;
  else
    goto invalid_value;

  return TRUE;

invalid_type:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_INVALID_ARGUMENT,
        "The 'aslr' option must be a string");
    return FALSE;
  }
invalid_value:
  {
    g_set_error (error,
        TELCO_ERROR,
        TELCO_ERROR_INVALID_ARGUMENT,
        "The 'aslr' option must be set to either 'auto' or 'disable'");
    return FALSE;
  }
}

static void
telco_mapper_library_blob_deallocate (TelcoMappedLibraryBlob * self)
{
  mach_vm_deallocate (mach_task_self (), self->address, self->allocated_size);

  telco_mapped_library_blob_free (self);
}
