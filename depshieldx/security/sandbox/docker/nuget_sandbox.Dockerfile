# Sandbox image for NuGet deep-mode installs and (a future stage) behavioral
# tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# maven_sandbox.Dockerfile/go_sandbox.Dockerfile -- the sandbox container's
# rootfs runs --read-only, so nothing can be apt-get installed at container
# run time. Neither python3 nor strace ship in the base image (confirmed
# directly: `which python3`/`which strace` both find nothing in
# mcr.microsoft.com/dotnet/sdk:8.0's real Debian bookworm base).
#
# Unlike maven_sandbox.Dockerfile, no build-time plugin pre-warming is
# needed here -- confirmed directly `dotnet restore` against a real local
# folder package source works cleanly under this project's full isolation
# posture (--network none, --read-only rootfs, --cap-drop ALL, non-root
# user) with zero extra setup: the .NET SDK ships everything `restore`
# itself needs built in, unlike Maven's `dependency:resolve`, which is
# itself a plugin goal requiring dozens of jars resolved from network
# first.
FROM mcr.microsoft.com/dotnet/sdk:8.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*
