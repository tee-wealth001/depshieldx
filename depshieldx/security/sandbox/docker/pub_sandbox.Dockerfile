# Sandbox image for Pub deep-mode installs and (a future stage) behavioral
# tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# nuget_sandbox.Dockerfile/maven_sandbox.Dockerfile/go_sandbox.Dockerfile --
# the sandbox container's rootfs runs --read-only, so nothing can be
# apt-get installed at container run time. Neither python3 nor strace
# ship in the base image (confirmed directly: `which python3`/`which
# strace` both find nothing in a real dart:3 image's Debian trixie base).
#
# Like NuGet, no build-time pre-warming is needed here -- confirmed
# directly `dart pub get --offline` against a real, pre-populated local
# PUB_CACHE (packages extracted directly under hosted/pub.dev/<name>-
# <version>/, confirmed directly this matches the real cache layout, no
# flattening needed the way Cargo's .crate archives need) works cleanly
# under this project's full isolation posture (--network none,
# --read-only rootfs, --cap-drop ALL, non-root user) with zero extra
# setup: the Dart SDK ships everything `pub get` itself needs built in.
# One real wrinkle, unlike NuGet's local-folder source: `dart pub get`
# writes its own bookkeeping into $PUB_CACHE itself (an "active_roots"
# directory) even in --offline mode, confirmed directly a read-only
# PUB_CACHE bind mount fails with a real "Read-only file system" error
# -- sandbox_wrapper_pub.py copies the mounted, pre-built cache into a
# writable tmpfs location before pointing $PUB_CACHE at it, rather than
# using the read-only bundle mount directly the way NuGet.Config can.
FROM dart:3
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*
