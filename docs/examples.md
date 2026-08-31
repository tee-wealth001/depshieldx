# Examples

Install one package:

```bash
depshieldx install fastapi
```

Install multiple packages:

```bash
depshieldx install langchain requests --deep
```

Scan only:

```bash
depshieldx scan fastapi --fast
depshieldx scan fastapi --deep
```

Use a requirements file:

```bash
depshieldx install -r requirements.txt
depshieldx scan -r requirements.txt --deep
```

Use a lockfile:

```bash
depshieldx install --lockfile uv.lock
depshieldx scan --lockfile uv.lock
```

Use a `pyproject.toml` file:

```bash
depshieldx install --pyproject pyproject.toml
depshieldx scan --pyproject pyproject.toml --deep
```

Open the local cache UI:

```bash
depshieldx ui
depshieldx ui --port 8765
depshieldx ui --no-open
```

Uninstall packages:

```bash
depshieldx uninstall requests
depshieldx uninstall -r requirements.txt
depshieldx uninstall --pyproject pyproject.toml
```

## npm packages and lockfiles

```bash
depshieldx scan left-pad --ecosystem npm
depshieldx install left-pad --ecosystem npm
depshieldx install left-pad is-odd --ecosystem npm
depshieldx scan --lockfile package-lock.json
depshieldx install --lockfile yarn.lock
depshieldx scan --lockfile pnpm-lock.yaml
```

## Cargo crates and lockfiles

```bash
depshieldx scan serde --ecosystem cargo
depshieldx install serde --ecosystem cargo
depshieldx install serde tokio --ecosystem cargo
depshieldx scan --lockfile Cargo.lock
depshieldx install --lockfile Cargo.lock
```

## Go modules and lockfiles

```bash
depshieldx scan github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors golang.org/x/text --ecosystem go
depshieldx scan --lockfile go.sum
depshieldx install --lockfile go.sum
```

## Maven coordinates

```bash
depshieldx scan org.apache.commons:commons-lang3:3.18.0 --ecosystem maven
depshieldx install com.google.code.gson:gson:2.11.0 --ecosystem maven
depshieldx install org.apache.commons:commons-lang3 --ecosystem maven
```

## NuGet packages and lockfiles

```bash
depshieldx scan Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json@13.0.3 --ecosystem nuget
depshieldx scan --lockfile packages.lock.json
depshieldx install --lockfile packages.lock.json
```

## Pub packages and lockfiles

```bash
depshieldx scan http --ecosystem pub
depshieldx install http@1.6.0 --ecosystem pub
depshieldx scan --lockfile pubspec.lock
depshieldx install --lockfile pubspec.lock
```

## RubyGems packages and lockfiles

```bash
depshieldx scan rack --ecosystem rubygems
depshieldx install rack@3.2.7 --ecosystem rubygems
depshieldx scan --lockfile Gemfile.lock
depshieldx install --lockfile Gemfile.lock
```

## Composer packages and lockfiles

```bash
depshieldx scan monolog/monolog --ecosystem composer
depshieldx install monolog/monolog@3.10.0 --ecosystem composer
depshieldx scan --lockfile composer.lock
depshieldx install --lockfile composer.lock
```
