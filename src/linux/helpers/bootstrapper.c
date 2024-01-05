#include "elf-parser.h"
#include "inject-context.h"

#include <alloca.h>
#include <stdalign.h>

#ifdef NOLIBC
# define AF_UNIX 1
# define SOCK_STREAM 1
# define PR_GET_DUMPABLE 3
# define PR_SET_DUMPABLE 4
# define RTLD_LAZY 1
#else
# include <errno.h>
# include <fcntl.h>
# include <signal.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <sys/prctl.h>
#endif
#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif
#define TELCO_GLIBC_RTLD_DLOPEN 0x80000000U

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define TELCO_STRINGIFY(identifier) _TELCO_STRINGIFY (identifier)
#define _TELCO_STRINGIFY(identifier) #identifier

#ifndef DF_1_PIE
# define DF_1_PIE 0x08000000
#endif

#ifndef AT_RANDOM
# define AT_RANDOM 25
#endif

#ifndef AT_EXECFN
# define AT_EXECFN  31
#endif

typedef struct _TelcoCollectLibcApiContext TelcoCollectLibcApiContext;
typedef struct _TelcoProcessLayout TelcoProcessLayout;
typedef struct _TelcoRDebug TelcoRDebug;
typedef int TelcoRState;
typedef struct _TelcoLinkMap TelcoLinkMap;
typedef struct _TelcoOpenFileForMappedRangeContext TelcoOpenFileForMappedRangeContext;
typedef struct _TelcoDetectRtldFlavorContext TelcoDetectRtldFlavorContext;
typedef struct _TelcoEntrypointParameters TelcoEntrypointParameters;
typedef ssize_t (* TelcoParseFunc) (void * data, size_t size, void * user_data);

struct _TelcoCollectLibcApiContext
{
  int total_missing;
  TelcoRtldFlavor rtld_flavor;
  TelcoLibcApi * api;
};

struct _TelcoProcessLayout
{
  ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size;
  ElfW(Half) phdr_count;
  ElfW(Ehdr) * interpreter;
  TelcoRtldFlavor rtld_flavor;
  TelcoRDebug * r_debug;
  void * r_brk;
  void * libc;
};

struct _TelcoRDebug
{
  int r_version;
  TelcoLinkMap * r_map;
  ElfW(Addr) r_brk;
  TelcoRState r_state;
  ElfW(Addr) r_ldbase;
};

enum _TelcoRState
{
  RT_CONSISTENT,
  RT_ADD,
  RT_DELETE
};

struct _TelcoLinkMap
{
  ElfW(Addr) l_addr;
  char * l_name;
  ElfW(Dyn) * l_ld;
  TelcoLinkMap * l_next;
  TelcoLinkMap * l_prev;
};

struct _TelcoOpenFileForMappedRangeContext
{
  void * base;
  int fd;
};

struct _TelcoDetectRtldFlavorContext
{
  ElfW(Ehdr) * interpreter;
  TelcoRtldFlavor flavor;
};

struct _TelcoEntrypointParameters
{
  intptr_t argc;
  char * argv[2];
  char * envp[1];
  ElfW(auxv_t) auxv[9];
};

static bool telco_resolve_libc_apis (const TelcoProcessLayout * layout, TelcoLibcApi * libc);
static bool telco_collect_libc_symbol (const TelcoElfExportDetails * details, void * user_data);
static bool telco_collect_android_linker_symbol (const TelcoElfExportDetails * details, void * user_data);

static bool telco_probe_process (size_t page_size, TelcoProcessLayout * layout);
static void telco_enumerate_module_symbols_on_disk (void * loaded_base, TelcoFoundElfSymbolFunc func, void * user_data);
static int telco_open_file_for_mapped_range_with_base (void * base);
static ssize_t telco_open_file_for_matching_maps_line (void * data, size_t size, void * user_data);
static TelcoRtldFlavor telco_detect_rtld_flavor (ElfW(Ehdr) * interpreter);
static TelcoRtldFlavor telco_infer_rtld_flavor_from_filename (const char * name);
static ssize_t telco_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data);
static bool telco_path_is_libc (const char * path, TelcoRtldFlavor rtld_flavor);
static ssize_t telco_parse_auxv_entry (void * data, size_t size, void * user_data);
static bool telco_collect_interpreter_symbol (const TelcoElfExportDetails * details, void * user_data);
static ssize_t telco_try_find_libc_from_maps_line (void * data, size_t size, void * user_data);
static void telco_try_load_libc_and_raise (TelcoBootstrapContext * ctx);
static int telco_libc_main (int argc, char * argv[]);
static void * telco_map_elf (TelcoBootstrapContext * ctx, const char * path, void ** entrypoint);

static void telco_parse_file (const char * path, TelcoParseFunc parse, void * user_data);
static size_t telco_parse_size (const char * str);
static bool telco_str_has_prefix (const char * str, const char * prefix);
static bool telco_str_has_suffix (const char * str, const char * suffix);

static int telco_socketpair (int domain, int type, int protocol, int sv[2]);
static int telco_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
TelcoBootstrapStatus
telco_bootstrap (TelcoBootstrapContext * ctx)
{
  TelcoLibcApi * libc = ctx->libc;
  TelcoProcessLayout process;

  if (!telco_probe_process (ctx->page_size, &process))
    return TELCO_BOOTSTRAP_AUXV_NOT_FOUND;

  ctx->rtld_flavor = process.rtld_flavor;
  ctx->rtld_base = process.interpreter;
  ctx->r_brk = process.r_brk;

  if (process.interpreter != NULL && process.libc == NULL)
    return TELCO_BOOTSTRAP_TOO_EARLY;

  if (process.interpreter == NULL && process.libc == NULL)
  {
    telco_try_load_libc_and_raise (ctx);
    return TELCO_BOOTSTRAP_LIBC_LOAD_ERROR;
  }

  if (!telco_resolve_libc_apis (&process, libc))
    return TELCO_BOOTSTRAP_LIBC_UNSUPPORTED;

  ctx->loader_base = mmap (NULL, ctx->loader_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ctx->loader_base == MAP_FAILED)
    return TELCO_BOOTSTRAP_MMAP_ERROR;

  ctx->ctrlfds[0] = -1;
  ctx->ctrlfds[1] = -1;
  if (ctx->enable_ctrlfds)
    telco_socketpair (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctx->ctrlfds);

  return TELCO_BOOTSTRAP_SUCCESS;
}

static bool
telco_resolve_libc_apis (const TelcoProcessLayout * layout, TelcoLibcApi * libc)
{
  TelcoCollectLibcApiContext ctx;

  memset (libc, 0, sizeof (TelcoLibcApi));
  libc->dlopen_flags = RTLD_LAZY;

  ctx.total_missing = 17;
  if (layout->rtld_flavor == TELCO_RTLD_ANDROID)
    ctx.total_missing -= 4;
  ctx.rtld_flavor = layout->rtld_flavor;
  ctx.api = libc;
  telco_elf_enumerate_exports (layout->libc, telco_collect_libc_symbol, &ctx);

  if (ctx.total_missing > 0 &&
      (libc->dlopen_flags & TELCO_GLIBC_RTLD_DLOPEN) != 0 &&
      libc->dlerror == NULL)
  {
    ctx.total_missing--;
  }

  if (ctx.total_missing == 2 &&
      libc->pthread_create == NULL &&
      libc->pthread_detach == NULL)
  {
    const void * pretend_caller_addr = libc->close;
    void * libpthread = libc->dlopen ("libpthread.so.0", libc->dlopen_flags, pretend_caller_addr);
    if (libpthread != NULL)
    {
      libc->pthread_create = libc->dlsym (libpthread, "pthread_create", pretend_caller_addr);
      if (libc->pthread_create != NULL)
        ctx.total_missing--;
      libc->pthread_detach = libc->dlsym (libpthread, "pthread_detach", pretend_caller_addr);
      if (libc->pthread_detach != NULL)
        ctx.total_missing--;
    }
  }

  if (ctx.total_missing != 0)
    return false;

  if (layout->rtld_flavor == TELCO_RTLD_ANDROID)
  {
    bool found_all_or_none;

    ctx.total_missing = 4;
    telco_elf_enumerate_exports (layout->interpreter, telco_collect_android_linker_symbol, &ctx);

    if (ctx.total_missing == 4)
      telco_enumerate_module_symbols_on_disk (layout->interpreter, telco_collect_android_linker_symbol, &ctx);

    found_all_or_none = ctx.total_missing == 0 || ctx.total_missing == 4;
    if (!found_all_or_none)
      return false;
  }

  return true;
}

static bool
telco_collect_libc_symbol (const TelcoElfExportDetails * details, void * user_data)
{
  TelcoCollectLibcApiContext * ctx = user_data;
  TelcoLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define TELCO_TRY_COLLECT(e) \
    TELCO_TRY_COLLECT_NAMED (e, TELCO_STRINGIFY (e))
#define TELCO_TRY_COLLECT_NAMED(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  TELCO_TRY_COLLECT (printf)
  TELCO_TRY_COLLECT (sprintf)

  TELCO_TRY_COLLECT (mmap)
  TELCO_TRY_COLLECT (munmap)
  TELCO_TRY_COLLECT (socket)
  TELCO_TRY_COLLECT (socketpair)
  TELCO_TRY_COLLECT (connect)
  TELCO_TRY_COLLECT (recvmsg)
  TELCO_TRY_COLLECT (send)
  TELCO_TRY_COLLECT (fcntl)
  TELCO_TRY_COLLECT (close)

  TELCO_TRY_COLLECT (pthread_create)
  TELCO_TRY_COLLECT (pthread_detach)

  if (ctx->rtld_flavor != TELCO_RTLD_ANDROID)
  {
    TELCO_TRY_COLLECT (dlopen)
    if (api->dlopen == NULL && strcmp (details->name, "__libc_dlopen_mode") == 0)
    {
      api->dlopen = details->address;
      api->dlopen_flags |= TELCO_GLIBC_RTLD_DLOPEN;
      ctx->total_missing--;
      goto beach;
    }

    TELCO_TRY_COLLECT (dlclose)
    TELCO_TRY_COLLECT_NAMED (dlclose, "__libc_dlclose")

    TELCO_TRY_COLLECT (dlsym)
    TELCO_TRY_COLLECT_NAMED (dlsym, "__libc_dlsym")

    TELCO_TRY_COLLECT (dlerror)
  }

#undef TELCO_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
telco_collect_android_linker_symbol (const TelcoElfExportDetails * details, void * user_data)
{
  TelcoCollectLibcApiContext * ctx = user_data;
  TelcoLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define TELCO_TRY_COLLECT(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  TELCO_TRY_COLLECT (dlopen, "__loader_dlopen");
  TELCO_TRY_COLLECT (dlclose, "__loader_dlclose");
  TELCO_TRY_COLLECT (dlsym, "__loader_dlsym");
  TELCO_TRY_COLLECT (dlerror, "__loader_dlerror");

  TELCO_TRY_COLLECT (dlopen, "__dl__Z8__dlopenPKciPKv");
  TELCO_TRY_COLLECT (dlclose, "__dl__Z9__dlclosePv");
  TELCO_TRY_COLLECT (dlsym, "__dl__Z7__dlsymPvPKcPKv");
  TELCO_TRY_COLLECT (dlerror, "__dl__Z9__dlerrorv");

#undef TELCO_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
telco_probe_process (size_t page_size, TelcoProcessLayout * layout)
{
  int previous_dumpable;
  bool use_proc_fallback;

  layout->phdrs = NULL;
  layout->phdr_size = 0;
  layout->phdr_count = 0;
  layout->interpreter = NULL;
  layout->rtld_flavor = TELCO_RTLD_UNKNOWN;
  layout->r_debug = NULL;
  layout->r_brk = NULL;
  layout->libc = NULL;

  previous_dumpable = telco_prctl (PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (previous_dumpable != -1 && previous_dumpable != 1)
    telco_prctl (PR_SET_DUMPABLE, 1, 0, 0, 0);

  telco_parse_file ("/proc/self/auxv", telco_parse_auxv_entry, layout);

  if (previous_dumpable != -1 && previous_dumpable != 1)
    telco_prctl (PR_SET_DUMPABLE, previous_dumpable, 0, 0, 0);

  if (layout->phdrs == NULL)
    return false;

  layout->rtld_flavor = telco_detect_rtld_flavor (layout->interpreter);

  if (layout->interpreter != NULL)
  {
    telco_elf_enumerate_exports (layout->interpreter, telco_collect_interpreter_symbol, layout);

    if (layout->r_debug == NULL)
      telco_enumerate_module_symbols_on_disk (layout->interpreter, telco_collect_interpreter_symbol, layout);

    if (layout->r_debug != NULL)
    {
      TelcoRDebug * r = layout->r_debug;
      TelcoLinkMap * map;

      for (map = r->r_map; map != NULL; map = map->l_next)
      {
        if (telco_path_is_libc (map->l_name, layout->rtld_flavor))
        {
          layout->libc = (void *) map->l_addr;
          break;
        }
      }

      /*
       * Injecting right after libc has been loaded appears to be risky, e.g. the program's observed __environ might be NULL.
       * So instead of waiting for r_brk to be executed again, we use the program's earliest initializer / entrypoint.
       *
       * This still leaves the issue where we might be attaching to a process in the brief moment right after libc has become
       * visible, but before it's been fully linked in. So we definitely want to move to a better strategy.
       */
      if (layout->libc == NULL && (map = r->r_map) != NULL)
      {
        const ElfW(Dyn) * entry;

        layout->r_brk = NULL;

        for (entry = map->l_ld; entry->d_tag != DT_NULL; entry++)
        {
          switch (entry->d_tag)
          {
            case DT_INIT:
              layout->r_brk = (void *) (entry->d_un.d_ptr + map->l_addr);
              break;
            case DT_PREINIT_ARRAY:
            case DT_INIT_ARRAY:
              if (layout->r_brk == NULL)
              {
                void * val = *((void **) (entry->d_un.d_ptr + map->l_addr));
                if (val != NULL && val != (void *) -1)
                  layout->r_brk = val;
              }
              break;
          }
        }

        if (layout->r_brk == NULL)
        {
          const ElfW(Ehdr) * program = (const ElfW(Ehdr) *)
              telco_elf_compute_base_from_phdrs (layout->phdrs, layout->phdr_size, layout->phdr_count, page_size);
          layout->r_brk = (void *) (program->e_entry + map->l_addr);
        }
      }

      use_proc_fallback = false;
    }
    else
    {
      use_proc_fallback = true;
    }
  }
  else
  {
    use_proc_fallback = true;
  }

  if (use_proc_fallback)
    telco_parse_file ("/proc/self/maps", telco_try_find_libc_from_maps_line, layout);

  return true;
}

static void
telco_enumerate_module_symbols_on_disk (void * loaded_base, TelcoFoundElfSymbolFunc func, void * user_data)
{
  int fd;
  off_t size;
  void * elf;

  fd = telco_open_file_for_mapped_range_with_base (loaded_base);
  if (fd == -1)
    return;
  size = lseek (fd, 0, SEEK_END);
  elf = mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

  telco_elf_enumerate_symbols (elf, loaded_base, func, user_data);

  munmap (elf, size);
  close (fd);
}

static int
telco_open_file_for_mapped_range_with_base (void * base)
{
  TelcoOpenFileForMappedRangeContext ctx;

  ctx.base = base;
  ctx.fd = -1;
  telco_parse_file ("/proc/self/maps", telco_open_file_for_matching_maps_line, &ctx);

  return ctx.fd;
}

static ssize_t
telco_open_file_for_matching_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  TelcoOpenFileForMappedRangeContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) telco_parse_size (line);
  if (base == ctx->base)
  {
    const char * path = strchr (line, '/');
    if (path != NULL)
    {
      ctx->fd = open (path, O_RDONLY);
      return -1;
    }
  }

  return (next_newline + 1) - (char *) data;
}

static TelcoRtldFlavor
telco_detect_rtld_flavor (ElfW(Ehdr) * interpreter)
{
  const char * soname;
  TelcoDetectRtldFlavorContext ctx;

  if (interpreter == NULL)
    return TELCO_RTLD_NONE;

  soname = telco_elf_query_soname (interpreter);
  if (soname != NULL)
    return telco_infer_rtld_flavor_from_filename (soname);

  ctx.interpreter = interpreter;
  ctx.flavor = TELCO_RTLD_UNKNOWN;
  telco_parse_file ("/proc/self/maps", telco_try_infer_rtld_flavor_from_maps_line, &ctx);

  return ctx.flavor;
}

static TelcoRtldFlavor
telco_infer_rtld_flavor_from_filename (const char * name)
{
  if (telco_str_has_prefix (name, "ld-linux-"))
    return TELCO_RTLD_GLIBC;

  if (telco_str_has_prefix (name, "ld-uClibc"))
    return TELCO_RTLD_UCLIBC;

  if (strcmp (name, "libc.so") == 0)
    return TELCO_RTLD_MUSL;

  if (strcmp (name, "ld-android.so") == 0)
    return TELCO_RTLD_ANDROID;
  if (strcmp (name, "linker") == 0)
    return TELCO_RTLD_ANDROID;
  if (strcmp (name, "linker64") == 0)
    return TELCO_RTLD_ANDROID;

  return TELCO_RTLD_UNKNOWN;
}

static ssize_t
telco_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  TelcoDetectRtldFlavorContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) telco_parse_size (line);

  if (base == ctx->interpreter)
  {
    const char * filename = strrchr (line, '/') + 1;
    ctx->flavor = telco_infer_rtld_flavor_from_filename (filename);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static bool
telco_path_is_libc (const char * path, TelcoRtldFlavor rtld_flavor)
{
  const char * last_slash, * name;

  if (rtld_flavor == TELCO_RTLD_ANDROID)
  {
    return telco_str_has_suffix (path, "/lib/libc.so") ||
        telco_str_has_suffix (path, "/lib64/libc.so") ||
        telco_str_has_suffix (path, "/bionic/libc.so");
  }

  last_slash = strrchr (path, '/');
  if (last_slash != NULL)
    name = last_slash + 1;
  else
    name = path;

  return telco_str_has_prefix (name, "libc.so");
}

static ssize_t
telco_parse_auxv_entry (void * data, size_t size, void * user_data)
{
  ElfW(auxv_t) * entry = data;
  TelcoProcessLayout * layout = user_data;

  if (size < sizeof (ElfW(auxv_t)))
    return 0;

  switch (entry->a_type)
  {
    case AT_PHDR:
      layout->phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
      break;
    case AT_PHENT:
      layout->phdr_size = entry->a_un.a_val;
      break;
    case AT_PHNUM:
      layout->phdr_count = entry->a_un.a_val;
      break;
    case AT_BASE:
      layout->interpreter = (ElfW(Ehdr) *) entry->a_un.a_val;
      break;
  }

  return sizeof (ElfW(auxv_t));
}

static bool
telco_collect_interpreter_symbol (const TelcoElfExportDetails * details, void * user_data)
{
  TelcoProcessLayout * layout = user_data;
  bool found_both;

  if (details->type == STT_OBJECT && (
        strcmp (details->name, "_r_debug") == 0 ||
        strcmp (details->name, "__dl__r_debug") == 0))
    layout->r_debug = details->address;

  if (details->type == STT_FUNC && (
        strcmp (details->name, "_dl_debug_state") == 0 ||
        strcmp (details->name, "rtld_db_dlactivity") == 0))
    layout->r_brk = details->address;

  found_both = layout->r_debug != NULL && layout->r_brk != NULL;
  return !found_both;
}

static ssize_t
telco_try_find_libc_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  TelcoProcessLayout * layout = user_data;
  char * next_newline, * path;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  path = strchr (line, '/');
  if (path != NULL && telco_path_is_libc (path, layout->rtld_flavor))
  {
    layout->libc = (void *) telco_parse_size (line);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static void
telco_try_load_libc_and_raise (TelcoBootstrapContext * ctx)
{
  void * ld, * entrypoint, * program;
  uint8_t dummy_random[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
  const char * ld_name = ctx->fallback_ld;
  const char * libc_name = ctx->fallback_libc;
  size_t phdr_offset = 64;
  size_t ld_name_offset = 256;
  size_t ld_name_size = strlen (ld_name) + 1;
  const char * strtab_data = libc_name;
  size_t strtab_offset = 384;
  size_t strtab_size = strlen (libc_name) + 1;
  size_t symtab_offset = 448;
  ElfW(Dyn) dyn[] = {
    {
      .d_tag = DT_NEEDED,
      .d_un.d_val = 0,
    },
    {
      .d_tag = DT_STRTAB,
      .d_un.d_ptr = strtab_offset,
    },
    {
      .d_tag = DT_STRSZ,
      .d_un.d_val = strtab_size,
    },
    {
      .d_tag = DT_SYMTAB,
      .d_un.d_ptr = symtab_offset,
    },
    {
      .d_tag = DT_SYMENT,
      .d_un.d_val = sizeof (ElfW(Sym)),
    },
    {
      .d_tag = DT_FLAGS_1,
      .d_un.d_val = DF_1_PIE,
    },
    {
      .d_tag = DT_NULL,
      .d_un.d_val = 0,
    },
  };
  size_t dyn_offset = 512;
  size_t dyn_size = sizeof (dyn);
  size_t entrypoint_offset = 1024;
  ElfW(Phdr) phdr[] = {
    {
      .p_type = PT_PHDR,
      .p_flags = PF_R,
      .p_offset = phdr_offset,
      .p_vaddr = phdr_offset,
      .p_paddr = phdr_offset,
      .p_align = 8,
    },
    {
      .p_type = PT_INTERP,
      .p_flags = PF_R,
      .p_offset = ld_name_offset,
      .p_vaddr = ld_name_offset,
      .p_paddr = ld_name_offset,
      .p_filesz = ld_name_size,
      .p_memsz = ld_name_size,
      .p_align = 1,
    },
    {
      .p_type = PT_DYNAMIC,
      .p_flags = PF_R | PF_W,
      .p_offset = dyn_offset,
      .p_vaddr = dyn_offset,
      .p_paddr = dyn_offset,
      .p_filesz = dyn_size,
      .p_memsz = dyn_size,
      .p_align = 8,
    },
  };
  ElfW(Ehdr) ehdr = {
    .e_ident = ELFMAG "\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    .e_type = ET_DYN,
    .e_machine = EM_X86_64,
    .e_version = EV_CURRENT,
    .e_entry = entrypoint_offset,
    .e_phoff = phdr_offset,
    .e_shoff = -1,
    .e_flags = 0,
    .e_ehsize = sizeof (ElfW(Ehdr)),
    .e_phentsize = sizeof (ElfW(Phdr)),
    .e_phnum = sizeof (phdr) / sizeof (phdr[0]),
    .e_shentsize = 0,
    .e_shnum = 0,
    .e_shstrndx = 0,
  };

  phdr[0].p_filesz = sizeof (phdr);
  phdr[0].p_memsz = sizeof (phdr);

  entrypoint = NULL;
  ld = telco_map_elf (ctx, ld_name, &entrypoint);
  if (ld == NULL)
    return;

  program = mmap (NULL, ctx->page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memmove (program, &ehdr, sizeof (ehdr));
  memmove (program + phdr_offset, phdr, sizeof (phdr));
  memmove (program + ld_name_offset, ld_name, ld_name_size);
  memmove (program + strtab_offset, strtab_data, strtab_size);
  memmove (program + dyn_offset, dyn, dyn_size);

  {
    alignas (16) TelcoEntrypointParameters params = {
      .argc = 1,
      .argv = {
        "/bin/program",
        NULL,
      },
      .envp = {
        NULL,
      },
      .auxv = {
        { .a_type = AT_PAGESZ, .a_un.a_val = ctx->page_size },
        { .a_type = AT_PHDR, .a_un.a_val = (size_t) (program + phdr_offset) },
        { .a_type = AT_PHENT, .a_un.a_val = sizeof (ElfW(Phdr)) },
        { .a_type = AT_PHNUM, .a_un.a_val = sizeof (phdr) / sizeof (phdr[0]) },
        { .a_type = AT_BASE, .a_un.a_val = (size_t) ld },
        { .a_type = AT_ENTRY, .a_un.a_val = (size_t) telco_libc_main },
        { .a_type = AT_RANDOM, .a_un.a_val = (ElfW(Addr)) dummy_random },
        { .a_type = AT_EXECFN, .a_un.a_val = (ElfW(Addr)) "/bin/program" },
        { .a_type = AT_NULL, .a_un.a_val = 0 },
      },
    };

#if defined (__i386__) || defined (__i486__) || defined (__i586__) || defined (__i686__)
    asm volatile (
        "mov %0, %%esp\n\t"
        "jmp *%1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__x86_64__)
    asm volatile (
        "mov %0, %%rsp\n\t"
        "jmp *%1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__ARM_EABI__)
    asm volatile (
        "mov sp, %0\n\t"
        "bx %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__aarch64__)
    asm volatile (
        "mov sp, %0\n\t"
        "br %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__mips__)
    asm volatile (
        "move $sp, %0\n\t"
        "jr %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#endif
  }
}

static int
telco_libc_main (int argc, char * argv[])
{
  raise (SIGSTOP);
  return 0;
}

static void *
telco_map_elf (TelcoBootstrapContext * ctx, const char * path, void ** entrypoint)
{
  bool success = false;
  int fd = -1;
  ElfW(Ehdr) ehdr;
  size_t phdrs_size;
  ElfW(Phdr) * phdrs;
  const ElfW(Addr) page_size = ctx->page_size;
  ElfW(Half) i;
  ElfW(Addr) lowest, highest;
  size_t footprint_size = 0;
  void * base = MAP_FAILED;
  void * previous_end;
  ElfW(Addr) bss_start, bss_end;
  size_t n;

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  if (read (fd, &ehdr, sizeof (ehdr)) != sizeof (ehdr))
    goto beach;

  if (lseek (fd, ehdr.e_phoff, SEEK_SET) == -1)
    goto beach;
  phdrs_size = ehdr.e_phnum * ehdr.e_phentsize;
  phdrs = alloca (phdrs_size);
  if (read (fd, phdrs, phdrs_size) != phdrs_size)
    goto beach;

  lowest = ~0;
  highest = 0;
  for (i = 0; i != ehdr.e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      lowest = MIN (TELCO_ELF_PAGE_START (phdr->p_vaddr, page_size), lowest);
      highest = MAX (phdr->p_vaddr + phdr->p_memsz, highest);
    }
  }

  footprint_size = highest - lowest;

  base = mmap (NULL, footprint_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED)
    goto beach;

  previous_end = NULL;

  bss_start = 0;
  bss_end = 0;

  for (i = 0; i != ehdr.e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      ElfW(Addr) relative_vaddr;
      ElfW(Addr) map_address;
      size_t gap_size, page_offset, map_offset, map_size;
      void * segment_base;
      ElfW(Word) flags = phdr->p_flags;
      int prot;

      relative_vaddr = phdr->p_vaddr - lowest;

      map_address = TELCO_ELF_PAGE_START (base + relative_vaddr, page_size);

      gap_size = (previous_end != NULL)
          ? (void *) map_address - previous_end
          : 0;
      if (gap_size != 0)
        munmap (previous_end, gap_size);

      page_offset = TELCO_ELF_PAGE_OFFSET (relative_vaddr, page_size);
      map_offset = phdr->p_offset - page_offset;
      map_size = TELCO_ELF_PAGE_ALIGN (phdr->p_filesz + page_offset, page_size);

      prot = 0;
      if ((flags & PF_R) != 0)
        prot |= PROT_READ;
      if ((flags & PF_W) != 0)
        prot |= PROT_WRITE;
      if ((flags & PF_X) != 0)
        prot |= PROT_EXEC;

      segment_base = mmap ((void *) map_address, map_size, prot, MAP_PRIVATE | MAP_FIXED, fd, map_offset);
      if (segment_base == MAP_FAILED)
        goto beach;

      previous_end = segment_base + map_size;

      bss_start = MAX ((ElfW(Addr)) base + relative_vaddr + phdr->p_filesz, bss_start);
      bss_end = MAX ((ElfW(Addr)) base + relative_vaddr + phdr->p_memsz, bss_end);
    }
  }

  n = TELCO_ELF_PAGE_OFFSET (bss_start, page_size);
  if (n != 0)
  {
    n = page_size - n;
    memset ((void *) bss_start, 0, n);
  }

  if (entrypoint != NULL)
    *entrypoint = base + ehdr.e_entry;

  success = true;

beach:
  if (!success && base != MAP_FAILED)
    munmap (base, footprint_size);

  if (fd != -1)
    close (fd);

  return success ? base : NULL;
}

static void
telco_parse_file (const char * path, TelcoParseFunc parse, void * user_data)
{
  int fd;
  char * cursor;
  size_t fill_amount;
  char buffer[2048];

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  fill_amount = 0;
  while (true)
  {
    ssize_t n;

    n = read (fd, buffer + fill_amount, sizeof (buffer) - fill_amount - 1);
    if (n > 0)
    {
      fill_amount += n;
      buffer[fill_amount] = '\0';
    }
    if (fill_amount == 0)
      break;

    cursor = buffer;
    while (true)
    {
      ssize_t n = parse (cursor, buffer + fill_amount - cursor, user_data);
      if (n == -1)
        goto beach;
      if (n == 0)
      {
        size_t consumed = cursor - buffer;
        if (consumed != 0)
        {
          memmove (buffer, buffer + consumed, fill_amount - consumed + 1);
          fill_amount -= consumed;
        }
        else
        {
          fill_amount = 0;
        }
        break;
      }

      cursor += n;
    }
  }

beach:
  if (fd != -1)
    close (fd);
}

static size_t
telco_parse_size (const char * str)
{
  size_t result = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    char ch = *cursor;

    if (ch >= '0' && ch <= '9')
      result = (result * 16) + (ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      result = (result * 16) + (10 + (ch - 'a'));
    else
      break;
  }

  return result;
}

static bool
telco_str_has_prefix (const char * str, const char * prefix)
{
  return strncmp (str, prefix, strlen (prefix)) == 0;
}

static bool
telco_str_has_suffix (const char * str, const char * suffix)
{
  size_t str_length, suffix_length;

  str_length = strlen (str);
  suffix_length = strlen (suffix);
  if (str_length < suffix_length)
    return false;

  return strcmp (str + str_length - suffix_length, suffix) == 0;
}

static int
telco_socketpair (int domain, int type, int protocol, int sv[2])
{
#ifdef NOLIBC
  return my_syscall4 (__NR_socketpair, domain, type, protocol, sv);
#else
  return socketpair (domain, type, protocol, sv);
#endif
}

static int
telco_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
#ifdef NOLIBC
  return my_syscall5 (__NR_prctl, option, arg2, arg3, arg4, arg5);
#else
  return prctl (option, arg2, arg3, arg4, arg5);
#endif
}

#ifdef BUILDING_TEST_PROGRAM

#include <stdio.h>
#include <strings.h>

int
main (void)
{
  TelcoLibcApi libc;
  TelcoBootstrapContext ctx;
  size_t result;

  bzero (&libc, sizeof (libc));

  bzero (&ctx, sizeof (ctx));
  ctx.page_size = getpagesize ();
  ctx.loader_size = 4096;
  ctx.enable_ctrlfds = true;
  ctx.libc = &libc;

  result = telco_bootstrap (&ctx);

  printf ("result: %zu\n", result);
  printf ("loader_base: %p\n", ctx.loader_base);

  return 0;
}

#endif
