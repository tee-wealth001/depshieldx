# Sandbox image for cargo deep-mode installs and (Stage 3) behavioral
# tracing.
#
# strace isn't needed until Stage 3, but this image is built here (Stage 2)
# since it's shared sandbox infrastructure, mirroring npm_sandbox.Dockerfile
# -- the sandbox container's rootfs runs --read-only, so nothing can be
# apt-get installed at container run time. rust:1-slim's Debian base has
# neither strace nor python3 preinstalled (confirmed directly for both) --
# python3 runs sandbox_wrapper_cargo.py, the same way node:20 needed no
# extra runtime for sandbox_wrapper_npm.js but python:3.11 already had one
# built in for PyPI's wrapper. Built and cached locally by sandbox.py on
# first use (docker image inspect / docker build) -- no external registry
# involved.
FROM rust:1-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*
