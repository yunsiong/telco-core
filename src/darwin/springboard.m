#import "springboard.h"

#include <dlfcn.h>
#include <gum/gum.h>

#define TELCO_ASSIGN_SBS_FUNC(N) \
    api->N = dlsym (api->sbs, G_STRINGIFY (N)); \
    g_assert (api->N != NULL)
#define TELCO_ASSIGN_SBS_CONSTANT(N) \
    str = dlsym (api->sbs, G_STRINGIFY (N)); \
    g_assert (str != NULL); \
    api->N = *str
#define TELCO_ASSIGN_FBS_CONSTANT(N) \
    str = dlsym (api->fbs, G_STRINGIFY (N)); \
    g_assert (str != NULL); \
    api->N = *str

#define TELCO_IOS_MOBILE_USER_ID 501

extern kern_return_t bootstrap_look_up (mach_port_t bp, const char * service_name, mach_port_t * sp);
extern kern_return_t bootstrap_look_up_per_user (mach_port_t bp, const char * service_name, uid_t target_user, mach_port_t * sp);

extern mach_port_t bootstrap_port;

static kern_return_t telco_replacement_bootstrap_look_up (mach_port_t bp, const char * service_name, mach_port_t * sp);
static kern_return_t telco_replacement_xpc_look_up_endpoint (const char * service_name, uint32_t type, uint64_t handle,
    uint64_t lookup_handle, const uint8_t * instance, uint64_t flags, void * cputypes, mach_port_t * port, bool * non_launching);

typedef kern_return_t (* TelcoXpcLookUpEndpointFunc) (const char * service_name, uint32_t type, uint64_t handle, uint64_t lookup_handle,
    const uint8_t * instance, uint64_t flags, void * cputypes, mach_port_t * port, bool * non_launching);

static TelcoXpcLookUpEndpointFunc telco_find_xpc_look_up_endpoint_implementation (void);
static gboolean telco_is_bl_imm (guint32 insn);

static TelcoSpringboardApi * telco_springboard_api = NULL;
static TelcoXpcLookUpEndpointFunc telco_xpc_look_up_endpoint;

TelcoSpringboardApi *
_telco_get_springboard_api (void)
{
  if (telco_springboard_api == NULL)
  {
    TelcoSpringboardApi * api;
    NSString ** str;
    id (* objc_get_class_impl) (const gchar * name);

    api = g_new0 (TelcoSpringboardApi, 1);

    api->sbs = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (api->sbs != NULL);

    api->fbs = dlopen ("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_GLOBAL | RTLD_LAZY);

    TELCO_ASSIGN_SBS_FUNC (SBSSpringBoardBackgroundServerPort);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyFrontmostApplicationDisplayIdentifier);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyApplicationDisplayIdentifiers);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyDisplayIdentifierForProcessID);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyLocalizedApplicationNameForDisplayIdentifier);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyIconImagePNGDataForDisplayIdentifier);
    TELCO_ASSIGN_SBS_FUNC (SBSCopyInfoForApplicationWithProcessID);
    TELCO_ASSIGN_SBS_FUNC (SBSLaunchApplicationWithIdentifierAndLaunchOptions);
    TELCO_ASSIGN_SBS_FUNC (SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions);
    TELCO_ASSIGN_SBS_FUNC (SBSApplicationLaunchingErrorString);

    TELCO_ASSIGN_SBS_CONSTANT (SBSApplicationLaunchOptionUnlockDeviceKey);

    objc_get_class_impl = dlsym (RTLD_DEFAULT, "objc_getClass");
    g_assert (objc_get_class_impl != NULL);

    if (api->fbs != NULL)
    {
      api->FBSSystemService = objc_get_class_impl ("FBSSystemService");
      g_assert (api->FBSSystemService != nil);

      TELCO_ASSIGN_FBS_CONSTANT (FBSOpenApplicationOptionKeyUnlockDevice);
      TELCO_ASSIGN_FBS_CONSTANT (FBSOpenApplicationOptionKeyDebuggingOptions);

      TELCO_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyArguments);
      TELCO_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyEnvironment);
      TELCO_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyStandardOutPath);
      TELCO_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyStandardErrorPath);
      TELCO_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyDisableASLR);
    }

    api->mcs = dlopen ("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (api->mcs != NULL);

    api->LSApplicationProxy = objc_get_class_impl ("LSApplicationProxy");
    g_assert (api->LSApplicationProxy != nil);

    api->LSApplicationWorkspace = objc_get_class_impl ("LSApplicationWorkspace");
    g_assert (api->LSApplicationWorkspace != nil);

#ifndef HAVE_TVOS
    if (api->SBSSpringBoardBackgroundServerPort () == MACH_PORT_NULL)
    {
      GumInterceptor * interceptor;

      interceptor = gum_interceptor_obtain ();

      gum_interceptor_replace (interceptor, bootstrap_look_up, telco_replacement_bootstrap_look_up, NULL, NULL);

      telco_xpc_look_up_endpoint = telco_find_xpc_look_up_endpoint_implementation ();
      if (telco_xpc_look_up_endpoint != NULL)
        gum_interceptor_replace (interceptor, telco_xpc_look_up_endpoint, telco_replacement_xpc_look_up_endpoint, NULL, NULL);
      else
        g_error ("Unable to locate _xpc_look_up_endpoint(); please file a bug");
    }
#endif

    telco_springboard_api = api;
  }

  return telco_springboard_api;
}

static kern_return_t
telco_replacement_bootstrap_look_up (mach_port_t bp, const char * service_name, mach_port_t * sp)
{
  if (strcmp (service_name, "com.apple.springboard.backgroundappservices") == 0)
    return bootstrap_look_up_per_user (bp, service_name, TELCO_IOS_MOBILE_USER_ID, sp);

  return bootstrap_look_up (bp, service_name, sp);
}

static kern_return_t
telco_replacement_xpc_look_up_endpoint (const char * service_name, uint32_t type, uint64_t handle, uint64_t lookup_handle,
    const uint8_t * instance, uint64_t flags, void * cputypes, mach_port_t * port, bool * non_launching)
{
  if (strcmp (service_name, "com.apple.containermanagerd") == 0 ||
      strcmp (service_name, "com.apple.frontboard.systemappservices") == 0 ||
      strcmp (service_name, "com.apple.lsd.icons") == 0 ||
      strcmp (service_name, "com.apple.lsd.mapdb") == 0 ||
      strcmp (service_name, "com.apple.runningboard") == 0 ||
      g_str_has_prefix (service_name, "com.apple.distributed_notifications"))
  {
    if (non_launching != NULL)
      *non_launching = false;
    return bootstrap_look_up_per_user (bootstrap_port, service_name, TELCO_IOS_MOBILE_USER_ID, port);
  }

  return telco_xpc_look_up_endpoint (service_name, type, handle, lookup_handle, instance, flags, cputypes, port, non_launching);
}

static TelcoXpcLookUpEndpointFunc
telco_find_xpc_look_up_endpoint_implementation (void)
{
  guint32 * cursor;

  cursor = GSIZE_TO_POINTER (
      gum_strip_code_address (gum_module_find_export_by_name ("/usr/lib/system/libxpc.dylib", "xpc_endpoint_create_bs_named")));
  if (cursor == NULL)
    return NULL;

  do
  {
    guint32 insn = *cursor;

    if (telco_is_bl_imm (insn))
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance;

      distance.u = insn & GUM_INT26_MASK;
      if ((distance.u & (1 << (26 - 1))) != 0)
        distance.u |= 0xfc000000;

      return (TelcoXpcLookUpEndpointFunc) (cursor + distance.i);
    }

    cursor++;
  }
  while (TRUE);
}

static gboolean
telco_is_bl_imm (guint32 insn)
{
  return (insn & ~GUM_INT26_MASK) == 0x94000000;
}
