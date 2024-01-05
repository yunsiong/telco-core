agent_sources = [
  'agent.vala',
  'agent-glue.c',
]

force_cpp_linking = have_v8
if force_cpp_linking
  agent_sources += ['dummy.cpp']
endif

extra_vala_args = []
extra_link_args = []
extra_link_depends = []

if host_os_family != 'windows'
  extra_vala_args += '--pkg=posix'
endif
if host_os_family == 'darwin'
  extra_vala_args += '--pkg=telco-gum-darwin-1.0'
endif

if host_os_family == 'windows'
  symfile = (host_arch == 'x86') ? 'telco-agent-x86.symbols' : 'telco-agent.symbols'
  extra_link_args += '-Wl,--retain-symbols-file,' + (meson.current_source_dir() / symfile)
  extra_link_depends += symfile
elif host_os_family == 'darwin'
  extra_link_args += '-Wl,-exported_symbol,_telco_agent_main'
else
  symscript = 'telco-agent.version'
  extra_link_args += '-Wl,--version-script,' + (meson.current_source_dir() / symscript)
  extra_link_depends += symscript
endif

if host_os_family in ['linux', 'qnx']
  # For our libc shim to be effective.
  extra_link_args += '-Wl,-Bsymbolic'
endif

raw_agent = shared_library('telco-agent', agent_sources,
  name_prefix: 'lib',
  c_args: telco_component_cflags,
  vala_args: extra_vala_args,
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  vs_module_defs: 'telco-agent.def',
  override_options: ['b_asneeded=true'],
  dependencies: [gio_dep, gee_dep, gum_dep, gumjs_dep, base_dep, pipe_dep, tls_provider_dep, payload_dep],
)

operations = ['--move', 'constructor', 'telco_init_memory', 'first']
if host_os_family != 'darwin'
  operations += ['--move', 'destructor', 'telco_deinit_memory', 'first']
endif

if host_machine.endian() == 'little'
  endian_option = ['--endian', 'little']
else
  endian_option = ['--endian', 'big']
endif

modulated_agent = custom_target('telco-agent-modulated',
  input: raw_agent,
  output: 'libtelco-agent-modulated' + shlib_suffix,
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

if host_os_family == 'darwin'
  identity = 'TelcoAgent'
else
  identity = agent_name
endif

agent = custom_target('telco-agent',
  input: modulated_agent,
  output: agent_name,
  command: [
    post_process_module,
    '@INPUT@',
    '@OUTPUT@',
    identity,
  ],
  build_by_default: true,
  install: get_option('assets') == 'installed',
  install_dir: asset_dir,
)

agent_dep = declare_dependency(link_with: agent)
