gadget_sources = [
  'gadget.vala',
  'gadget-glue.c',
]

if host_os_family == 'darwin'
  gadget_sources += 'gadget-darwin.m'
endif

force_cpp_linking = have_v8
if force_cpp_linking
  gadget_sources += 'dummy.cpp'
endif

platform_deps = []

extra_objc_args = []
extra_link_args = []
extra_link_depends = []

if host_os_family != 'windows'
  platform_deps += gio_unix_dep
endif

if host_os_family == 'darwin'
  extra_objc_args += '-fobjc-arc'
  extra_link_args += '-Wl,-framework,Foundation'
endif

if host_os_family == 'windows'
  symfile = 'telco-gadget.symbols'
  extra_link_args += '-Wl,--retain-symbols-file,' + (meson.current_source_dir() / symfile)
  extra_link_depends += symfile
elif host_os_family == 'darwin'
  symlist = 'telco-gadget.symbols'
  extra_link_args += '-Wl,-exported_symbols_list,' + (meson.current_source_dir() / symlist)
  extra_link_depends += symlist
else
  symscript = 'telco-gadget.version'
  extra_link_args += '-Wl,--version-script,' + (meson.current_source_dir() / symscript)
  extra_link_depends += symscript
endif

if host_os_family in ['linux', 'qnx']
  # For our libc shim to be effective.
  extra_link_args += ['-Wl,-Bsymbolic']
endif

raw_gadget = shared_library('telco-gadget', gadget_sources,
  name_prefix: 'lib',
  c_args: telco_component_cflags,
  objc_args: extra_objc_args,
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  vs_module_defs: 'telco-gadget.def',
  override_options: ['b_asneeded=true'],
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, base_dep, tls_provider_dep, payload_dep] + platform_deps,
)

operations = [
  '--move', 'constructor', 'telco_init_memory', 'first',
  '--move', 'constructor', 'telco_on_load', 'last',
]
if host_os_family != 'darwin'
  operations += [
    '--move', 'destructor', 'telco_deinit_memory', 'first',
    '--move', 'destructor', 'telco_on_unload', 'last',
  ]
endif
if get_option('strip')
  operations += ['--strip', '>>>', strip, '<<<']
endif

if host_machine.endian() == 'little'
  endian_option = ['--endian', 'little']
else
  endian_option = ['--endian', 'big']
endif

modulated_gadget = custom_target('telco-gadget-modulated',
  input: raw_gadget,
  output: 'libtelco-gadget-modulated' + shlib_suffix,
  command: [
    modulate,
    '@INPUT@',
    ] + operations + endian_option + [
    '--output', '@OUTPUT@',
    '--nm', nm,
    '--readelf', readelf,
    '--otool', otool,
  ],
)

if host_os == 'macos'
  identity = '@executable_path/../Frameworks/TelcoGadget.dylib'
elif host_os in ['ios', 'tvos']
  identity = '@executable_path/Frameworks/TelcoGadget.dylib'
else
  identity = gadget_name
endif

custom_target('telco-gadget',
  input: modulated_gadget,
  output: gadget_name,
  command: [
    post_process_module,
    '@INPUT@',
    '@OUTPUT@',
    identity,
  ],
  install: true,
  install_dir: asset_dir,
)
