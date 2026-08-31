# Maven / Maven Central Support

`depshieldx` can resolve, check, and install Maven coordinates too, with full fast and
deep mode support.

Maven has no canonical lockfile to auto-detect the way
`Cargo.lock`/`go.sum`/`package-lock.json` do, so coordinates are always passed
explicitly with `--ecosystem maven`:

```bash
depshieldx scan org.apache.commons:commons-lang3:3.18.0 --ecosystem maven
depshieldx install com.google.code.gson:gson:2.11.0 --ecosystem maven
depshieldx install org.apache.commons:commons-lang3 --ecosystem maven
```

A bare `groupId:artifactId` (no version) resolves to that coordinate's latest release
via Maven Central's search API. Resolution shells out to the real `mvn` CLI against a
scratch `pom.xml` in an isolated temp directory (`dependency:list`) to compute the
full, accurate transitive dependency graph, the same reasoning as Cargo's/Go's
scratch-project resolve.

"Install" here means fetching every resolved coordinate -- transitive
dependencies included, not just the ones you named -- into your local repository
(`~/.m2`), pinned exactly so nothing can drift between scan and install. There is no
`depshieldx uninstall` support for Maven: `mvn dependency:get`/`dependency:resolve`
only ever download into the local repository, they never edit a `pom.xml` the way
`cargo remove`/`go get @none` edit their manifests, so there's nothing well-defined to
reverse. There is also no [routing shim](../cli/routing.md) for Maven -- unlike
`pip install`/`npm install`/`cargo add`/`go get`, Maven has no native CLI verb for
"add a dependency" to intercept; dependencies are added by editing `pom.xml` directly.

`--deep` is supported the same way it is for PyPI, npm, Cargo, and Go: the resolved
coordinate set (every real `.jar` and `.pom`, plus every `<parent>` POM and
`<dependencyManagement>` BOM import needed to resolve them, walked recursively) is
fetched into a sandboxed container (`maven:3-eclipse-temurin-21` + `strace`, with
Maven's own default-lifecycle plugin set pre-warmed into the image at build time) and
scanned with Trivy -- Trivy reads the scratch `pom.xml` natively. The sandboxed
`mvn compile` is traced with `strace` for filesystem, process, and network activity
-- see [Modes](../concepts/modes.md) for details. Unlike Cargo's `build.rs` or
Go's `init()`, a jar consumed as a plain Maven dependency runs no code automatically;
the one real exception is an annotation processor registered via
`META-INF/services`, which gets discovered and invoked by `javac` during any compile
it's present for -- ordinary libraries that register no processor correctly
trace zero build-time activity.

Provenance checks for Maven combine checksum verification (SHA-256 where published,
falling back to SHA-1 for older releases -- MD5 is never trusted), structural
PGP-signature presence (Maven Central has required PGP signatures since the 2010s, but
with no central root of trust `depshieldx` can verify against), and real cryptographic
Sigstore verification where a publisher has opted in (supported by Maven Central's
Publisher Portal since January 2025) -- see
[Provenance & Attestations](../concepts/provenance.md).

## Not supported

- `depshieldx uninstall` -- see above, there's no well-defined manifest edit to
  reverse
- the [routing shim](../cli/routing.md) -- Maven has no native "add a dependency"
  CLI command to intercept
- `pom.xml`-as-input -- only explicit `groupId:artifactId[:version]` coordinates
  via `--ecosystem maven` are accepted, no lockfile or manifest auto-detection
