# Routing

`depshieldx` can optionally install small shims so simple `pip install <package>`,
`npm install [package]`, `yarn install`, `pnpm install`, `cargo add <crate>`,
`go get <module>`, `dotnet add package <name>`, `dart pub add <package...>`,
`bundle add <gem...>`, and `composer require <package...>` commands go through
`depshieldx`.

```bash
depshieldx routing status
depshieldx routing enable
depshieldx routing disable
```

Routing is platform-aware:

- on macOS and Linux it creates shell shims (`pip`, `npm`, `yarn`, `pnpm`, `cargo`,
  `go`, `dotnet`, `dart`, `bundle`, `composer`)
- on Windows it creates batch shims (`pip.bat`, `npm.bat`, `yarn.bat`, `pnpm.bat`,
  `cargo.bat`, `go.bat`, `dotnet.bat`, `dart.bat`, `bundle.bat`, `composer.bat`)

## What each shim intercepts

- `pip install <package>` -- a single package name, routed through
  `depshieldx install <package>`
- `npm install` / `npm i` / `npm ci` / `yarn install` / `pnpm install` with no
  package named -- routed through
  `depshieldx install --lockfile <lockfile-in-cwd>`, only when that lockfile is
  present
- `npm install <package...>` / `npm i <package...>` -- one or more package
  names with no other flags, routed through
  `depshieldx install <package...> --ecosystem npm`
- `yarn add <package>` / `pnpm add <package>` are **not** intercepted yet --
  ad-hoc resolution in this phase only covers `npm install <package>`, so yarn/pnpm
  named installs pass straight through to the real tool
- `cargo add <crate...>` -- one or more crate names with no other flags,
  routed through `depshieldx install <crate...> --ecosystem cargo`. `cargo install`
  (binary crates) is not intercepted -- depshieldx's cargo support only covers
  `cargo add`
- `go get <module...>` -- one or more module paths with no other flags,
  routed through `depshieldx install <module...> --ecosystem go`. `go install`
  (binary programs) is not intercepted -- depshieldx's Go support only covers
  `go get`
- `dotnet add package <name>` / `dotnet add package <name> --version <version>`
  -- exactly one package, no other flags, routed through
  `depshieldx install <name>[@version] --ecosystem nuget`. No project positional
  and no other `dotnet add package` flags (`--framework`, `--prerelease`, ...) are
  intercepted -- anything beyond this exact shape passes straight through to
  the real `dotnet`
- `dart pub add <package...>` -- one or more package names with no other
  flags, routed through `depshieldx install <package...> --ecosystem pub`.
  Non-hosted descriptor syntax (`"foo@{path: ...}"`, `"foo@{git: ...}"`,
  `"foo@{sdk: ...}"`) and section prefixes (`dev:foo`, `override:foo`) are not
  intercepted -- depshieldx's Pub support only covers hosted (pub.dev)
  packages, and anything using that syntax passes straight through to the real
  `dart`
- `bundle add <gem...>` (no other flags) -- one or more gem names, routed
  through `depshieldx install <gem...> --ecosystem rubygems`.
  `bundle add <gem> --version <version>` (exactly one gem) is also intercepted,
  routed through `depshieldx install <gem>@<version> --ecosystem rubygems`.
  `bundle add <gem1> <gem2> --version <version>` (a shared version across multiple
  gems -- confirmed this is real Bundler behavior) is **not** intercepted,
  since that shape doesn't map to a safe per-gem depshieldx target; it passes
  straight through to the real `bundle`
- `composer require <package...>` (no other flags) -- one or more
  `vendor/package[:constraint]` targets, routed through
  `depshieldx install <package...> --ecosystem composer`. Unlike depshieldx's own
  "name@version" convention (always an exact pin elsewhere in this project),
  Composer's own "name:constraint" syntax accepts arbitrary ranges and branch
  aliases, not just exact versions -- a colon-target whose constraint isn't a
  plain exact version is **not** intercepted, and the whole command passes
  straight through to the real `composer` rather than risk silently
  misrepresenting a range as a pin

There is no Maven shim, and none is planned -- unlike `pip install`/
`npm install`/`cargo add`/`go get`/`dotnet add package`/`dart pub add`/
`bundle add`/`composer require`, `mvn` has no native CLI verb for "add a
dependency" to intercept in the first place; Maven dependencies are added by
editing `pom.xml` directly. See [Maven support](../ecosystems/maven.md).

Anything else (flags mixed in with a package name, other subcommands like `run`,
global installs) passes straight through to the real tool untouched.

## Useful environment variables

- `DEPSHIELDX_CACHE_DIR`
- `DEPSHIELDX_RECEIPTS_DIR`
- `DEPSHIELDX_NO_ROUTING_PROMPT=1`
- `DEPSHIELDX_ROUTE_DEEP=1`
