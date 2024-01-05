generate_api = files('generate.py')

core_vapi = join_paths(core_build_dir, 'telco-core.vapi')
core_header = join_paths(core_build_dir, 'telco-core.h')
base_vapi = join_paths(base_build_dir, f'telco-base-@api_version@.vapi')
base_header = join_paths(base_build_dir, 'telco-base.h')

custom_target('telco-core-header',
  input: [core, base],
  output: ['telco-core.h'],
  command: [
    generate_api,
    '--output=header',
    api_version,
    core_vapi, core_header,
    base_vapi, base_header,
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: header_install_dir,
)

custom_target('telco-core-vapi',
  input: [core, base],
  output: [
    'telco-core-@0@.vapi'.format(api_version),
    'telco-core-@0@.deps'.format(api_version)
  ],
  command: [
    generate_api,
    '--output=vapi',
    api_version,
    core_vapi, core_header,
    base_vapi, base_header,
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: join_paths(get_option('datadir'), 'vala', 'vapi'),
)

custom_target('telco-core-library',
  input: [core] + internal_libs,
  output: 'libtelco-core-@0@.a'.format(api_version),
  command: [
    files('merge.sh'),
    ar,
    libtool,
    meson.current_build_dir(),
    '@OUTPUT@',
    '@INPUT@'
  ],
  install: true,
  install_dir: get_option('libdir'),
)

pkg = import('pkgconfig')
pkg.generate(filebase: 'telco-core-' + api_version,
  name: 'Telco Core',
  version: meson.project_version(),
  description: 'Telco core library intended for static linking into bindings',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0'],
  requires_private: ['gmodule-2.0', 'gee-0.8', libsoup_dep, 'telco-gum-1.0', 'telco-gumjs-inspector-1.0', 'libbrotlidec'] + backend_deps_private,
  subdirs: 'telco-' + api_version,
  libraries: ['-L${libdir}', '-ltelco-core-' + api_version],
  libraries_private: backend_libs_private,
)
