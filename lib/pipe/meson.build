pipe_sources = [
  'pipe.vala',
]

system_deps = []
vala_args = []

if host_os_family == 'windows'
  pipe_sources += [
    'pipe-windows.c',
    'pipe-sddl.c',
  ]
elif host_os in ['macos', 'ios', 'tvos']
  pipe_sources += ['pipe-darwin.c']

  system_deps += [gio_unix_dep]
  vala_args += ['--pkg=telco-gum-darwin-1.0', '--pkg=posix']
else
  pipe_sources += ['pipe-unix.c']

  system_deps += [gio_unix_dep]
  vala_args += ['--pkg=posix']
endif

if host_os == 'android'
  system_deps += [telco_selinux_dep]
  vala_args += telco_selinux_vala_args
endif

pipe = static_library('telco-pipe', pipe_sources,
  c_args: telco_component_cflags,
  vala_args: vala_args,
  vala_header: 'telco-pipe.h',
  dependencies: [glib_dep, gobject_dep, gio_dep, gee_dep, base_dep] + system_deps,
)

pipe_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: pipe,
)
