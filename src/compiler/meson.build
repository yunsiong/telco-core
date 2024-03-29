compiler_sources = files(
  'compiler.vala',
)

if get_option('compiler_snapshot').auto()
  # Generating our snapshot with V8's CPU simulator takes a very long time.
  use_snapshot = meson.can_run_host_binaries()
else
  use_snapshot = get_option('compiler_snapshot').enabled()
endif
compiler_mksnapshot = use_snapshot ? v8_mksnapshot : ''

compiler_agent = custom_target('frida-compiler-agent',
  input: [
    'agent-entrypoint.js',
    'agent-core.ts',
    'agent-warmup.js',
    'package.json',
    'package-lock.json',
    'tsconfig.json',
    'rollup.config.agent-core.ts',
    'rollup.config.typescript.ts',
  ],
  output: [
    'agent.js',
    'snapshot.bin',
  ],
  command: [
    find_program('generate-agent.py'),
    meson.current_source_dir(),
    meson.current_build_dir(),
    host_os_family,
    host_arch_gumjs,
    host_cpu_mode,
    compiler_mksnapshot,
  ],
)
compiler_data = custom_target('telco-data-compiler',
  input: [
    'compiler.resources',
    compiler_agent,
  ],
  output: [
    'telco-data-compiler.vapi',
    'telco-data-compiler.h',
    'telco-data-compiler.c',
    'telco-data-compiler-blob.S',
  ],
  command: [
    resource_compiler,
    '--toolchain=' + host_toolchain,
    '-c', '@INPUT0@',
    '-o', join_paths(meson.current_build_dir(), 'telco-data-compiler'),
    '@INPUT1@',
    '@INPUT2@',
  ],
)
compiler_sources += compiler_data
