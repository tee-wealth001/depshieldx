# Sandbox image for Maven deep-mode installs and (a future stage) behavioral
# tracing.
#
# strace isn't needed until behavioral tracing lands, but this image is
# built here since it's shared sandbox infrastructure, mirroring
# go_sandbox.Dockerfile -- the sandbox container's rootfs runs --read-only,
# so nothing can be apt-get installed at container run time. Neither
# python3 nor strace ship in the base image (confirmed directly: `which
# python3`/`which strace` both find nothing in maven:3-eclipse-temurin-21).
#
# The real, Maven-specific problem cargo/go's sandbox images don't have:
# `dependency:resolve` is itself a Maven *plugin* goal, and Maven always
# resolves the full default-lifecycle plugin set for the project's
# packaging (resources/compiler/jar/surefire/install/deploy/site, plus the
# dependency plugin itself) just to load the project descriptor, before
# any goal actually runs -- confirmed directly against a real, from-empty
# local repository: `mvn dependency:resolve` needs ~51 plugin/dependency
# jars resolved before it can do anything, and none of those can be
# fetched once the sandboxed run itself is offline. So, unlike rust:1-slim
# (ships cargo) or golang:1-bookworm (ships go), this image also has to
# pre-warm a real local repository with Maven's own tooling at build time
# (network available here), which sandbox_wrapper_maven.py then merges
# with the host-provided, per-run project dependencies at container start
# -- see that file's docstring for why a merge, not pointing
# -Dmaven.repo.local at either location directly, is needed.
#
# world-readable (a+rX), not left at the default ~/.m2 (root's home,
# confirmed mode 0700) -- SANDBOX_USER runs as uid 65534 ("nobody"), which
# cannot traverse root's home directory at all, confirmed directly this
# fails with Permission denied otherwise.
FROM maven:3-eclipse-temurin-21
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/depshieldx-maven-plugin-cache /tmp/depshieldx-plugin-warm \
    && printf '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>depshieldx.scratch</groupId>\n  <artifactId>depshieldx-plugin-warm</artifactId>\n  <version>0.0.0</version>\n</project>\n' > /tmp/depshieldx-plugin-warm/pom.xml \
    && mvn -B -Dmaven.repo.local=/opt/depshieldx-maven-plugin-cache -f /tmp/depshieldx-plugin-warm/pom.xml dependency:resolve \
    && rm -rf /tmp/depshieldx-plugin-warm \
    && chmod -R a+rX /opt/depshieldx-maven-plugin-cache
