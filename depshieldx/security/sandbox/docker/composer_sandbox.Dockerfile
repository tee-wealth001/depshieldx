# Sandbox image for Composer deep-mode installs and (a future stage)
# behavioral tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# rubygems_sandbox.Dockerfile/pub_sandbox.Dockerfile -- the sandbox
# container's rootfs runs --read-only, so nothing can be apt-get installed
# at container run time.
#
# php:8.4-cli (confirmed directly, not assumed) already ships gcc/make
# (it's buildpack-deps-based, the same reason ruby:3 was chosen over
# ruby:3-slim) and curl/mbstring/openssl/Phar -- Composer's own real
# runtime requirements -- but NOT the `zip` extension: confirmed directly
# `ZipArchive` doesn't exist in the base image, and Composer's own real
# "artifact" repository mechanism (this project's offline-install
# mechanism -- see ecosystems/composer/ecosystem.py's module docstring)
# needs it. `docker-php-ext-install zip` (the official image's own
# extension-build helper) needs libzip-dev's headers at build time, which
# apt-get pulls in here. python3 is also confirmed missing (needed to run
# sandbox_wrapper_composer.py itself, the same gap nuget_sandbox.
# Dockerfile/go_sandbox.Dockerfile/cargo_sandbox.Dockerfile/pub_sandbox.
# Dockerfile each independently confirmed for their own base images).
#
# `unzip` is not strictly required -- confirmed directly Composer falls
# back to its own PHP ZipArchive extraction without it, successfully --
# but doing so prints an explicit warning about lost UNIX file
# permissions inside extracted archives. Installed here to get the clean,
# unwarned path Composer itself recommends, mirroring this project's
# general preference for a toolchain's own default-recommended behavior
# over a documented fallback path (the same reasoning ruby:3 was chosen
# over -slim for).
#
# No git/hg/fossil/svn: Composer's root-package version-detection tries
# each in turn (confirmed directly via a real install's own command log)
# but degrades gracefully with no error when none are present (correctly
# defaulting the scratch project's own version to "1.0.0") -- confirmed
# directly a real offline install still succeeds end-to-end without any
# of them installed, so none are added here.
#
# Composer itself is copied straight from the official composer:2 image
# (the documented, recommended way to add Composer to a custom PHP image)
# rather than run as a separate installer script.
FROM php:8.4-cli
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace libzip-dev unzip python3 \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
