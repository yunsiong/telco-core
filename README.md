# telco-core

Telco core library intended for static linking into bindings.

- Lets you inject your own JavaScript instrumentation code into other processes,
  optionally with your own [C code][] for performance-sensitive bits.
- Acts as a logistics layer that packages up [GumJS][] into a shared library.
- Provides a two-way communication channel for talking to your scripts,
  if needed, and later unload them.
- Also lets you enumerate installed apps, running processes, and connected
  devices.
- Written in [Vala][], with OS-specific glue code in C/Objective-C/asm.

## Binaries

Typically used through one of the available language bindings:

- [Python][]
- [Node.js][]
- [.NET][]
- [Swift][]
- [Qml][]

E.g.:

```console
$ pip install telco-tools # CLI tools
$ pip install telco # Python bindings
$ npm install telco # Node.js bindings
```

Or, for static linking into your own project written in a C-compatible language,
download a devkit from the Telco [releases][] page.

## Internals

For a higher level view of the internals, check out the [architecture diagram][]
and its links to the different parts of the codebase.


[C code]: https://telco.re/docs/javascript-api/#cmodule
[Vala]: https://wiki.gnome.org/Projects/Vala
[GumJS]: https://github.com/yunsiong/telco-gum
[Python]: https://github.com/yunsiong/telco-python
[Node.js]: https://github.com/yunsiong/telco-node
[.NET]: https://github.com/yunsiong/telco-clr
[Swift]: https://github.com/yunsiong/telco-swift
[Qml]: https://github.com/yunsiong/telco-qml
[releases]: https://github.com/yunsiong/telco/releases
[architecture diagram]: https://telco.re/docs/hacking/
