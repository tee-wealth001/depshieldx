# Sandbox image for npm deep-mode behavioral tracing (Stage 3).
#
# node:20 (the image used for npm deep mode's install/Trivy step in Stage 2)
# has no strace -- confirmed directly (`which strace` -> not found) -- and
# the sandbox container's rootfs runs --read-only, so strace can't be
# apt-get installed at container run time either. This image extends node:20
# with strace baked in at build time instead. Built and cached locally by
# sandbox.py on first use (docker image inspect / docker build) -- no
# external registry involved, matching how the rest of depshieldx already
# only depends on the npm/PyPI registries and Docker Hub base images
# directly.
FROM node:20
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
