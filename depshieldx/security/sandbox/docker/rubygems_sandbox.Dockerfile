# Sandbox image for RubyGems deep-mode installs and (a future stage)
# behavioral tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# nuget_sandbox.Dockerfile/maven_sandbox.Dockerfile/pub_sandbox.Dockerfile --
# the sandbox container's rootfs runs --read-only, so nothing can be
# apt-get installed at container run time.
#
# Unlike every other ecosystem's sandbox image here, plain `ruby:3` (not
# `-slim`) is deliberately used: confirmed directly `ruby:3-slim` has
# neither gcc nor make, while `ruby:3` (based on buildpack-deps) ships
# both -- and RubyGems' own real code-execution surface (a native-
# extension gem's `extconf.rb`, run by `bundle install` itself, no
# separate build step the way Cargo's build.rs/NuGet's SDK checks are)
# genuinely needs a C toolchain to complete successfully rather than
# spuriously "failing" for one of the ecosystem's most common package
# shapes (nokogiri, sqlite3, pg, bcrypt, ...). python3 already ships in
# `ruby:3` (confirmed directly), unlike node:20/rust:1-slim/dart:3, which
# all needed it installed explicitly -- only strace is missing here.
#
# `bundle install` (with or without --local) is never run on the HOST --
# confirmed directly it triggers real native-extension compilation
# (extconf.rb) as an inherent, unavoidable part of installing a gem that
# has one, unlike `cargo fetch --locked`/`go mod download`/`dotnet
# restore --locked-mode`/`dart pub get --offline`, none of which invoke a
# compiler. Fetching/checksum-verifying raw .gem files and producing
# Gemfile.lock both happen host-side without ever invoking `bundle`
# (see runner.py's prepare_rubygems_download_bundle) -- only inside this
# already fully-isolated container (--network none, --read-only rootfs,
# --cap-drop ALL, non-root user) does `bundle install --local` actually
# run, the same way every other ecosystem's own "real install-shaped
# operation" already runs inside its own sandbox here.
FROM ruby:3
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
