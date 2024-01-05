barebone_sources = []

if quickjs_dep.found()
  barebone_sources += files(
    'barebone-host-session.vala',
    'script.vala',
    'machine.vala',
    'allocator.vala',
    'callback.vala',
    'memory-scanner.vala',
    'interceptor.vala',
    'rust-module.vala',
    'arch-x86/machine.vala',
    'arch-x86_64/machine.vala',
    'arch-arm/machine.vala',
    'arch-arm64/machine.vala',
    'arch-unknown/machine.vala',
  )
  barebone_script_runtime = custom_target('telco-barebone-script-runtime',
    input: [
      'package.json',
      'package-lock.json',
      'script-runtime/console.ts',
      'script-runtime/entrypoint.ts',
      'script-runtime/gdb.ts',
      'script-runtime/hexdump.ts',
      'script-runtime/message-dispatcher.ts',
      'script-runtime/primitives.ts',
    ],
    output: [
      'script-runtime.js',
    ],
    command: [
      find_program('generate-script-runtime.py'),
      meson.current_source_dir(),
      meson.current_build_dir(),
    ],
  )
  barebone_data = custom_target('telco-data-barebone',
    input: [
      'barebone.resources',
      barebone_script_runtime,
      'helpers/memory-scanner-arm64.elf',
    ],
    output: [
      'telco-data-barebone.vapi',
      'telco-data-barebone.h',
      'telco-data-barebone.c',
      'telco-data-barebone-blob.S',
    ],
    command: [
      resource_compiler,
      '--toolchain=' + host_toolchain,
      '-c', '@INPUT0@',
      '-o', join_paths(meson.current_build_dir(), 'telco-data-barebone'),
      '@INPUT1@',
      '@INPUT2@',
    ],
  )
  barebone_sources += barebone_data

  backend_deps += quickjs_dep
endif
