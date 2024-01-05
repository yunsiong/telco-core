#include "upload-api.h"

#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

#define TELCO_INT2_MASK  0x00000003U
#define TELCO_INT11_MASK 0x000007ffU
#define TELCO_INT16_MASK 0x0000ffffU
#define TELCO_INT32_MASK 0xffffffffU

typedef uint8_t TelcoUploadCommandType;
typedef uint8_t TelcoDarwinThreadedItemType;

typedef void (* TelcoConstructorFunc) (int argc, const char * argv[], const char * env[], const char * apple[], int * result);

typedef struct _TelcoChainedFixupsHeader TelcoChainedFixupsHeader;

typedef struct _TelcoChainedStartsInImage TelcoChainedStartsInImage;
typedef struct _TelcoChainedStartsInSegment TelcoChainedStartsInSegment;
typedef uint16_t TelcoChainedPtrFormat;

typedef struct _TelcoChainedPtr64Rebase TelcoChainedPtr64Rebase;
typedef struct _TelcoChainedPtr64Bind TelcoChainedPtr64Bind;
typedef struct _TelcoChainedPtrArm64eRebase TelcoChainedPtrArm64eRebase;
typedef struct _TelcoChainedPtrArm64eBind TelcoChainedPtrArm64eBind;
typedef struct _TelcoChainedPtrArm64eBind24 TelcoChainedPtrArm64eBind24;
typedef struct _TelcoChainedPtrArm64eAuthRebase TelcoChainedPtrArm64eAuthRebase;
typedef struct _TelcoChainedPtrArm64eAuthBind TelcoChainedPtrArm64eAuthBind;
typedef struct _TelcoChainedPtrArm64eAuthBind24 TelcoChainedPtrArm64eAuthBind24;

typedef uint32_t TelcoChainedImportFormat;
typedef uint32_t TelcoChainedSymbolFormat;

typedef struct _TelcoChainedImport TelcoChainedImport;
typedef struct _TelcoChainedImportAddend TelcoChainedImportAddend;
typedef struct _TelcoChainedImportAddend64 TelcoChainedImportAddend64;

enum _TelcoUploadCommandType
{
  TELCO_UPLOAD_COMMAND_WRITE = 1,
  TELCO_UPLOAD_COMMAND_APPLY_THREADED,
  TELCO_UPLOAD_COMMAND_PROCESS_FIXUPS,
  TELCO_UPLOAD_COMMAND_PROTECT,
  TELCO_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS,
  TELCO_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS,
  TELCO_UPLOAD_COMMAND_CHECK,
};

enum _TelcoDarwinThreadedItemType
{
  TELCO_DARWIN_THREADED_REBASE,
  TELCO_DARWIN_THREADED_BIND
};

struct _TelcoChainedFixupsHeader
{
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  TelcoChainedImportFormat imports_format;
  TelcoChainedSymbolFormat symbols_format;
};

struct _TelcoChainedStartsInImage
{
  uint32_t seg_count;
  uint32_t seg_info_offset[1];
};

struct _TelcoChainedStartsInSegment
{
  uint32_t size;
  uint16_t page_size;
  TelcoChainedPtrFormat pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  uint16_t page_start[1];
};

enum _TelcoChainedPtrStart
{
  TELCO_CHAINED_PTR_START_NONE  = 0xffff,
  TELCO_CHAINED_PTR_START_MULTI = 0x8000,
  TELCO_CHAINED_PTR_START_LAST  = 0x8000,
};

enum _TelcoChainedPtrFormat
{
  TELCO_CHAINED_PTR_ARM64E              =  1,
  TELCO_CHAINED_PTR_64                  =  2,
  TELCO_CHAINED_PTR_32                  =  3,
  TELCO_CHAINED_PTR_32_CACHE            =  4,
  TELCO_CHAINED_PTR_32_FIRMWARE         =  5,
  TELCO_CHAINED_PTR_64_OFFSET           =  6,
  TELCO_CHAINED_PTR_ARM64E_OFFSET       =  7,
  TELCO_CHAINED_PTR_ARM64E_KERNEL       =  7,
  TELCO_CHAINED_PTR_64_KERNEL_CACHE     =  8,
  TELCO_CHAINED_PTR_ARM64E_USERLAND     =  9,
  TELCO_CHAINED_PTR_ARM64E_FIRMWARE     = 10,
  TELCO_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
  TELCO_CHAINED_PTR_ARM64E_USERLAND24   = 12,
};

struct _TelcoChainedPtr64Rebase
{
  uint64_t target   : 36,
           high8    :  8,
           reserved :  7,
           next     : 12,
           bind     :  1;
};

struct _TelcoChainedPtr64Bind
{
  uint64_t ordinal  : 24,
           addend   :  8,
           reserved : 19,
           next     : 12,
           bind     :  1;
};

struct _TelcoChainedPtrArm64eRebase
{
  uint64_t target : 43,
           high8  :  8,
           next   : 11,
           bind   :  1,
           auth   :  1;
};

struct _TelcoChainedPtrArm64eBind
{
  uint64_t ordinal : 16,
           zero    : 16,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _TelcoChainedPtrArm64eBind24
{
  uint64_t ordinal : 24,
           zero    :  8,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _TelcoChainedPtrArm64eAuthRebase
{
  uint64_t target    : 32,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _TelcoChainedPtrArm64eAuthBind
{
  uint64_t ordinal   : 16,
           zero      : 16,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _TelcoChainedPtrArm64eAuthBind24
{
  uint64_t ordinal   : 24,
           zero      :  8,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

enum _TelcoChainedImportFormat
{
  TELCO_CHAINED_IMPORT          = 1,
  TELCO_CHAINED_IMPORT_ADDEND   = 2,
  TELCO_CHAINED_IMPORT_ADDEND64 = 3,
};

enum _TelcoChainedSymbolFormat
{
  TELCO_CHAINED_SYMBOL_UNCOMPRESSED,
  TELCO_CHAINED_SYMBOL_ZLIB_COMPRESSED,
};

struct _TelcoChainedImport
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
};

struct _TelcoChainedImportAddend
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
  int32_t  addend;
};

struct _TelcoChainedImportAddend64
{
  uint64_t lib_ordinal : 16,
           weak_import :  1,
           reserved    : 15,
           name_offset : 32;
  uint64_t addend;
};

#define TELCO_TEMP_FAILURE_RETRY(expression) \
  ({ \
    ssize_t __result; \
    \
    do __result = expression; \
    while (__result == -1 && *(api->get_errno_storage ()) == EINTR); \
    \
    __result; \
  })

static void telco_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions);

static void telco_process_chained_fixups (const TelcoChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const TelcoUploadApi * api);
static void telco_process_chained_fixups_in_segment_generic64 (void * cursor, TelcoChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void telco_process_chained_fixups_in_segment_arm64e (void * cursor, TelcoChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void * telco_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const TelcoUploadApi * api);

static void * telco_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr);
static const char * telco_symbol_name_from_darwin (const char * name);
static int64_t telco_sign_extend_int19 (uint64_t i19);

static bool telco_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const TelcoUploadApi * api);
static bool telco_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const TelcoUploadApi * api);

int64_t
telco_receive (int listener_fd, uint64_t session_id_top, uint64_t session_id_bottom, const char * apple[], const TelcoUploadApi * api)
{
  int result = 0;
  bool expecting_client;
  int res;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int client_fd;
  uint32_t ACK_MAGIC = 0xac4ac4ac;

  expecting_client = true;

  do
  {
    uint64_t client_sid[2];

    addr_len = sizeof (addr);

    res = TELCO_TEMP_FAILURE_RETRY (api->accept (listener_fd, (struct sockaddr *) &addr, &addr_len));
    if (res == -1)
      goto beach;
    client_fd = res;

    #define TELCO_READ_VALUE(v) \
        if (!telco_read_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    #define TELCO_WRITE_VALUE(v) \
        if (!telco_write_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    TELCO_READ_VALUE (client_sid);
    if (client_sid[0] != session_id_top || client_sid[1] != session_id_bottom)
      goto next_client;

    expecting_client = false;

    TELCO_WRITE_VALUE (ACK_MAGIC);

    while (true)
    {
      bool success = false;
      TelcoUploadCommandType command_type;

      TELCO_READ_VALUE (command_type);

      switch (command_type)
      {
        case TELCO_UPLOAD_COMMAND_WRITE:
        {
          uint64_t address;
          uint32_t size;
          size_t n;

          TELCO_READ_VALUE (address);
          TELCO_READ_VALUE (size);

          success = telco_read_chunk (client_fd, (void *) address, size, &n, api);

          api->sys_icache_invalidate ((void *) address, n);
          api->sys_dcache_flush ((void *) address, n);

          break;
        }
        case TELCO_UPLOAD_COMMAND_APPLY_THREADED:
        {
          uint64_t preferred_base_address, slide;
          uint16_t num_symbols, num_regions;

          TELCO_READ_VALUE (preferred_base_address);
          TELCO_READ_VALUE (slide);

          TELCO_READ_VALUE (num_symbols);
          uint64_t symbols[num_symbols];
          if (!telco_read_chunk (client_fd, symbols, num_symbols * sizeof (uint64_t), NULL, api))
            goto next_client;

          TELCO_READ_VALUE (num_regions);
          uint64_t regions[num_regions];
          if (!telco_read_chunk (client_fd, regions, num_regions * sizeof (uint64_t), NULL, api))
            goto next_client;

          telco_apply_threaded_items (preferred_base_address, slide, num_symbols, symbols, num_regions, regions);

          success = true;

          break;
        }
        case TELCO_UPLOAD_COMMAND_PROCESS_FIXUPS:
        {
          uint64_t fixups_header_address, mach_header_address, preferred_base_address;

          TELCO_READ_VALUE (fixups_header_address);
          TELCO_READ_VALUE (mach_header_address);
          TELCO_READ_VALUE (preferred_base_address);

          telco_process_chained_fixups ((const TelcoChainedFixupsHeader *) fixups_header_address,
              (struct mach_header_64 *) mach_header_address, (size_t) preferred_base_address, api);

          success = true;

          break;
        }
        case TELCO_UPLOAD_COMMAND_PROTECT:
        {
          uint64_t address;
          uint32_t size;
          int32_t prot;

          TELCO_READ_VALUE (address);
          TELCO_READ_VALUE (size);
          TELCO_READ_VALUE (prot);

          success = api->mprotect ((void *) address, size, prot) == 0;

          break;
        }
        case TELCO_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS:
        {
          uint64_t address;
          uint32_t count;
          TelcoConstructorFunc * constructors;
          uint32_t i;

          TELCO_READ_VALUE (address);
          TELCO_READ_VALUE (count);

          constructors = (TelcoConstructorFunc *) address;

          for (i = 0; i != count; i++)
          {
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructors[i] (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case TELCO_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS:
        {
          uint64_t address;
          uint32_t count;
          uint64_t mach_header_address;
          uint32_t * constructor_offsets;
          uint32_t i;

          TELCO_READ_VALUE (address);
          TELCO_READ_VALUE (count);
          TELCO_READ_VALUE (mach_header_address);

          constructor_offsets = (uint32_t *) address;

          for (i = 0; i != count; i++)
          {
            TelcoConstructorFunc constructor;
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructor = (TelcoConstructorFunc) (mach_header_address + constructor_offsets[i]);

            constructor (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case TELCO_UPLOAD_COMMAND_CHECK:
        {
          TELCO_WRITE_VALUE (ACK_MAGIC);

          success = true;

          break;
        }
      }

      if (!success)
        goto next_client;
    }

next_client:
    api->close (client_fd);
  }
  while (expecting_client);

beach:
  api->close (listener_fd);

  return result;
}

static void
telco_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions)
{
  uint16_t i;

  for (i = 0; i != num_regions; i++)
  {
    uint64_t * slot = (uint64_t *) regions[i];
    uint16_t delta;

    do
    {
      uint64_t value;
      bool is_authenticated;
      TelcoDarwinThreadedItemType type;
      uint8_t key;
      bool has_address_diversity;
      uint16_t diversity;
      uint64_t bound_value;

      value = *slot;

      is_authenticated      = (value >> 63) & 1;
      type                  = (value >> 62) & 1;
      delta                 = (value >> 51) & TELCO_INT11_MASK;
      key                   = (value >> 49) & TELCO_INT2_MASK;
      has_address_diversity = (value >> 48) & 1;
      diversity             = (value >> 32) & TELCO_INT16_MASK;

      if (type == TELCO_DARWIN_THREADED_BIND)
      {
        uint16_t bind_ordinal;

        bind_ordinal = value & TELCO_INT16_MASK;

        bound_value = symbols[bind_ordinal];
      }
      else if (type == TELCO_DARWIN_THREADED_REBASE)
      {
        uint64_t rebase_address;

        if (is_authenticated)
        {
          rebase_address = value & TELCO_INT32_MASK;
        }
        else
        {
          uint64_t top_8_bits, bottom_43_bits, sign_bits;
          bool sign_bit_set;

          top_8_bits = (value << 13) & 0xff00000000000000UL;
          bottom_43_bits = value     & 0x000007ffffffffffUL;

          sign_bit_set = (value >> 42) & 1;
          if (sign_bit_set)
            sign_bits = 0x00fff80000000000UL;
          else
            sign_bits = 0;

          rebase_address = top_8_bits | sign_bits | bottom_43_bits;
        }

        bound_value = rebase_address;

        if (is_authenticated)
          bound_value += preferred_base_address;

        bound_value += slide;
      }

      if (is_authenticated)
      {
        *slot = (uint64_t) telco_sign_pointer ((void *) bound_value, key, diversity, has_address_diversity, slot);
      }
      else
      {
        *slot = bound_value;
      }

      slot += delta;
    }
    while (delta != 0);
  }
}

static void
telco_process_chained_fixups (const TelcoChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const TelcoUploadApi * api)
{
  mach_port_t task;
  mach_vm_address_t slab_start;
  size_t slab_size;
  void * slab_cursor;
  void ** dylib_handles;
  size_t dylib_count;
  const void * command;
  uint32_t command_index;
  void ** bound_pointers;
  size_t bound_count, i;
  const char * symbols;
  const TelcoChainedStartsInImage * image_starts;
  uint32_t seg_index;

  task = api->_mach_task_self ();

  slab_start = 0;
  slab_size = 64 * 1024;
  api->mach_vm_allocate (task, &slab_start, slab_size, VM_FLAGS_ANYWHERE);
  slab_cursor = (void *) slab_start;

  dylib_handles = slab_cursor;
  dylib_count = 0;

  command = mach_header + 1;
  for (command_index = 0; command_index != mach_header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    switch (lc->cmd)
    {
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const char * name = command + dc->dylib.name.offset;

        dylib_handles[dylib_count++] = api->dlopen (name, RTLD_LAZY | RTLD_GLOBAL);

        break;
      }
      default:
        break;
    }

    command += lc->cmdsize;
  }

  slab_cursor += dylib_count * sizeof (void *);

  bound_pointers = slab_cursor;
  bound_count = fixups_header->imports_count;
  slab_cursor += bound_count * sizeof (void *);

  symbols = (const char *) fixups_header + fixups_header->symbols_offset;

  switch (fixups_header->imports_format)
  {
    case TELCO_CHAINED_IMPORT:
    {
      const TelcoChainedImport * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const TelcoChainedImport * import = &imports[i];

        bound_pointers[i] = telco_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
      }

      break;
    }
    case TELCO_CHAINED_IMPORT_ADDEND:
    {
      const TelcoChainedImportAddend * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const TelcoChainedImportAddend * import = &imports[i];

        bound_pointers[i] = telco_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
    case TELCO_CHAINED_IMPORT_ADDEND64:
    {
      const TelcoChainedImportAddend64 * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const TelcoChainedImportAddend64 * import = &imports[i];

        bound_pointers[i] = telco_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
  }

  image_starts = (const TelcoChainedStartsInImage *) ((const void *) fixups_header + fixups_header->starts_offset);

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const uint32_t seg_offset = image_starts->seg_info_offset[seg_index];
    const TelcoChainedStartsInSegment * seg_starts;
    TelcoChainedPtrFormat format;
    uint16_t page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const TelcoChainedStartsInSegment *) ((const void *) image_starts + seg_offset);
    format = seg_starts->pointer_format;

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      uint16_t start;
      void * cursor;

      start = seg_starts->page_start[page_index];
      if (start == TELCO_CHAINED_PTR_START_NONE)
        continue;
      /* Ignoring MULTI for now as it only applies to 32-bit formats. */

      cursor = (void *) mach_header + seg_starts->segment_offset + (page_index * seg_starts->page_size) + start;

      if (format == TELCO_CHAINED_PTR_64 || format == TELCO_CHAINED_PTR_64_OFFSET)
      {
        telco_process_chained_fixups_in_segment_generic64 (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
      else
      {
        telco_process_chained_fixups_in_segment_arm64e (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
    }
  }

  api->mach_vm_deallocate (task, slab_start, slab_size);
}

static void
telco_process_chained_fixups_in_segment_generic64 (void * cursor, TelcoChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 4;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    if ((*slot >> 63) == 0)
    {
      TelcoChainedPtr64Rebase * item = cursor;
      uint64_t top_8_bits, bottom_36_bits, unpacked_target;

      delta = item->next;

      top_8_bits = (uint64_t) item->high8 << (64 - 8);
      bottom_36_bits = item->target;
      unpacked_target = top_8_bits | bottom_36_bits;

      if (format == TELCO_CHAINED_PTR_64_OFFSET)
        *slot = actual_base_address + unpacked_target;
      else
        *slot = unpacked_target + slide;
    }
    else
    {
      TelcoChainedPtr64Bind * item = cursor;

      delta = item->next;

      *slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void
telco_process_chained_fixups_in_segment_arm64e (void * cursor, TelcoChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 8;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    switch (*slot >> 62)
    {
      case 0b00:
      {
        TelcoChainedPtrArm64eRebase * item = cursor;
        uint64_t top_8_bits, bottom_43_bits, unpacked_target;

        delta = item->next;

        top_8_bits = (uint64_t) item->high8 << (64 - 8);
        bottom_43_bits = item->target;

        unpacked_target = top_8_bits | bottom_43_bits;

        if (format == TELCO_CHAINED_PTR_ARM64E)
          *slot = unpacked_target + slide;
        else
          *slot = actual_base_address + unpacked_target;

        break;
      }
      case 0b01:
      {
        TelcoChainedPtrArm64eBind * item = cursor;
        TelcoChainedPtrArm64eBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == TELCO_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) (bound_pointers[ordinal] +
            telco_sign_extend_int19 (item->addend));

        break;
      }
      case 0b10:
      {
        TelcoChainedPtrArm64eAuthRebase * item = cursor;

        delta = item->next;

        *slot = (uint64_t) telco_sign_pointer ((void *) (preferred_base_address + item->target + slide), item->key, item->diversity,
            item->addr_div, slot);

        break;
      }
      case 0b11:
      {
        TelcoChainedPtrArm64eAuthBind * item = cursor;
        TelcoChainedPtrArm64eAuthBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == TELCO_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) telco_sign_pointer (bound_pointers[ordinal], item->key, item->diversity, item->addr_div, slot);

        break;
      }
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void *
telco_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const TelcoUploadApi * api)
{
  void * result;
  const char * raw_name, * name;

  if (dylib_ordinal <= 0)
    return NULL; /* Placeholder if we ever need to support this. */

  raw_name = symbol_strings + symbol_offset;
  name = telco_symbol_name_from_darwin (raw_name);

  result = api->dlsym (dylib_handles[dylib_ordinal - 1], name);

  result = ptrauth_strip (result, ptrauth_key_asia);

  return result;
}

static void *
telco_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr)
{
  void * p = ptr;
  uintptr_t d = diversity;

  if (use_address_diversity)
    d = ptrauth_blend_discriminator (address_of_ptr, d);

  switch (key)
  {
    case ptrauth_key_asia:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
      break;
    case ptrauth_key_asib:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
      break;
    case ptrauth_key_asda:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
      break;
    case ptrauth_key_asdb:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
      break;
  }

  return p;
}

static const char *
telco_symbol_name_from_darwin (const char * name)
{
  return (name[0] == '_') ? name + 1 : name;
}

static int64_t
telco_sign_extend_int19 (uint64_t i19)
{
  int64_t result;
  bool sign_bit_set;

  result = i19;

  sign_bit_set = i19 >> (19 - 1);
  if (sign_bit_set)
    result |= 0xfffffffffff80000ULL;

  return result;
}

static bool
telco_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const TelcoUploadApi * api)
{
  void * cursor = buffer;
  size_t remaining = length;

  if (bytes_read != NULL)
    *bytes_read = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = TELCO_TEMP_FAILURE_RETRY (api->read (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_read != NULL)
      *bytes_read += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static bool
telco_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const TelcoUploadApi * api)
{
  const void * cursor = buffer;
  size_t remaining = length;

  if (bytes_written != NULL)
    *bytes_written = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = TELCO_TEMP_FAILURE_RETRY (api->write (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_written != NULL)
      *bytes_written += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <pthread.h>
#include <stdio.h>

# undef BUILDING_TEST_PROGRAM
# include "upload-listener.c"
# define BUILDING_TEST_PROGRAM
# undef TELCO_WRITE_VALUE

typedef struct _TelcoTestState TelcoTestState;

struct _TelcoTestState
{
  uint16_t port;

  uint64_t session_id_top;
  uint64_t session_id_bottom;

  uint8_t target_a[4];
  uint8_t target_b[2];

  const TelcoUploadApi * api;
};

static void * telco_emulate_client (void * user_data);

int
main (void)
{
  const TelcoUploadApi api = TELCO_UPLOAD_API_INIT;
  uint64_t result;
  uint8_t error_code;
  uint32_t listener_fd;
  uint16_t port;
  pthread_t client_thread;
  TelcoTestState state;
  const char * apple[] = { NULL };

  result = telco_listen (TELCO_RX_BUFFER_SIZE, &api);

  error_code  = (result >> 56) & 0xff;
  listener_fd = (result >> 16) & 0xffffffff;
  port        =  result        & 0xffff;

  printf ("listen() => error_code=%u fd=%u port=%u\n", error_code, listener_fd, port);

  assert (error_code == 0);

  state.port = port;

  state.session_id_top = 1;
  state.session_id_bottom = 2;

  state.target_a[0] = 0;
  state.target_a[1] = 0;
  state.target_a[2] = 3;
  state.target_a[3] = 4;
  state.target_b[0] = 0;
  state.target_b[1] = 6;

  state.api = &api;

  pthread_create (&client_thread, NULL, telco_emulate_client, &state);

  telco_receive (listener_fd, 1, 2, apple, &api);

  pthread_join (client_thread, NULL);

  assert (state.target_a[0] == 1);
  assert (state.target_a[1] == 2);
  assert (state.target_a[2] == 3);
  assert (state.target_a[3] == 4);
  assert (state.target_b[0] == 5);
  assert (state.target_b[1] == 6);

  return 0;
}

static void *
telco_emulate_client (void * user_data)
{
  TelcoTestState * state = user_data;
  const TelcoUploadApi * api = state->api;
  struct sockaddr_in addr;
  int fd;
  int res;
  bool success;
  const TelcoUploadCommandType write_command_type = TELCO_UPLOAD_COMMAND_WRITE;
  uint64_t address;
  uint32_t size;
  uint8_t val_a[2], val_b;

  fd = api->socket (AF_INET, SOCK_STREAM, 0);
  assert (fd != -1);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (state->port);

  res = TELCO_TEMP_FAILURE_RETRY (connect (fd, (const struct sockaddr *) &addr, sizeof (addr)));
  assert (res != -1);

  #define TELCO_WRITE_VALUE(v) \
      success = telco_write_chunk (fd, &(v), sizeof (v), NULL, api); \
      assert (success)

  TELCO_WRITE_VALUE (state->session_id_top);
  TELCO_WRITE_VALUE (state->session_id_bottom);

  TELCO_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_a;
  TELCO_WRITE_VALUE (address);
  size = 2;
  TELCO_WRITE_VALUE (size);
  val_a[0] = 1;
  val_a[1] = 2;
  TELCO_WRITE_VALUE (val_a);

  TELCO_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_b;
  TELCO_WRITE_VALUE (address);
  size = 1;
  TELCO_WRITE_VALUE (size);
  val_b = 5;
  TELCO_WRITE_VALUE (val_b);

  api->close (fd);

  return NULL;
}

#endif
