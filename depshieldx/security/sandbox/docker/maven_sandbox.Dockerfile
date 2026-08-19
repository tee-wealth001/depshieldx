# Sandbox image for Maven deep-mode installs and (Stage 3) behavioral
# tracing.
#
# python3 and strace don't ship in the base image (confirmed directly:
# `which python3`/`which strace` both find nothing in maven:3-eclipse-
# temurin-21), and the sandbox container's rootfs runs --read-only, so
# neither can be apt-get installed at container run time.
#
# The real, Maven-specific problem cargo/go's sandbox images don't have:
# both `dependency:resolve` (Stage 2) and `compile` (Stage 3, this file's
# current version) are themselves Maven *plugin* goals, and Maven always
# resolves the full default-lifecycle plugin set for the project's
# packaging (resources/compiler/jar/surefire/install/deploy/site, plus
# whichever plugin was explicitly invoked) just to load the project
# descriptor, before any goal actually runs -- confirmed directly against
# a real, from-empty local repository: a real `compile` (not just
# `dependency:resolve`) needs ~71 plugin/dependency jars resolved before
# it can do anything (the ~51 dependency:resolve needs, plus ~20 more --
# plexus-compiler-javac, qdox, commons-io, and the rest of maven-
# compiler-plugin's own dependency chain -- confirmed directly these
# aren't touched by dependency:resolve alone, only once compile is
# actually invoked), none of which can be fetched once the sandboxed run
# itself is offline. So, unlike rust:1-slim (ships cargo) or golang:1-
# bookworm (ships go), this image also has to pre-warm a real local
# repository with Maven's own tooling at build time (network available
# here), which sandbox_wrapper_maven.py then merges with the host-
# provided, per-run project dependencies at container start -- see that
# file's docstring for why a merge, not pointing -Dmaven.repo.local at
# either location directly, is needed.
#
# world-readable (a+rX), not left at the default ~/.m2 (root's home,
# confirmed mode 0700) -- SANDBOX_USER runs as uid 65534 ("nobody"), which
# cannot traverse root's home directory at all, confirmed directly this
# fails with Permission denied otherwise.
FROM maven:3-eclipse-temurin-21
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/depshieldx-maven-plugin-cache /tmp/depshieldx-plugin-warm/src/main/java \
    && printf '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>depshieldx.scratch</groupId>\n  <artifactId>depshieldx-plugin-warm</artifactId>\n  <version>0.0.0</version>\n  <properties>\n    <maven.compiler.source>21</maven.compiler.source>\n    <maven.compiler.target>21</maven.compiler.target>\n  </properties>\n</project>\n' > /tmp/depshieldx-plugin-warm/pom.xml \
    && printf 'public class DepshieldxPluginWarmProbe {}\n' > /tmp/depshieldx-plugin-warm/src/main/java/DepshieldxPluginWarmProbe.java \
    && mvn -B -Dmaven.repo.local=/opt/depshieldx-maven-plugin-cache -f /tmp/depshieldx-plugin-warm/pom.xml compile \
    && rm -rf /tmp/depshieldx-plugin-warm \
    && chmod -R a+rX /opt/depshieldx-maven-plugin-cache
