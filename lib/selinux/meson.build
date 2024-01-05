telco_selinux_incdir = include_directories('.')

install_headers('telco-selinux.h', subdir: 'telco-' + api_version)

telco_selinux = static_library('telco-selinux', 'patch.c',
  c_args: telco_component_cflags,
  dependencies: [glib_dep, libselinux_dep, libsepol_dep],
)

telco_selinux_dep = declare_dependency(
  include_directories: telco_selinux_incdir,
  link_with: telco_selinux,
)

telco_selinux_vala_args = ['--pkg=libselinux']
