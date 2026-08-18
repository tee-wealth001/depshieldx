# Sandbox image for Go deep-mode installs and (a future stage) behavioral
# tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# cargo_sandbox.Dockerfile -- the sandbox container's rootfs runs
# --read-only, so nothing can be apt-get installed at container run time.
# Unlike rust:1-slim, golang:1-bookworm's Debian base already ships
# python3 (confirmed directly: `which python3` -> /usr/bin/python3) --
# still installed explicitly below for robustness against that changing in
# a future base image update, matching the other two Dockerfiles' pattern
# exactly. strace is confirmed missing either way. There is no
# "golang:1-slim" tag (confirmed directly against Docker Hub's real tag
# list for the official golang image) -- golang:1-bookworm is the closest
# equivalent to rust:1-slim/node:20's Debian base.
FROM golang:1-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*
