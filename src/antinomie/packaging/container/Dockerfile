# The container builder's image: Debian 13 (trixie) with the base build kit's
# tool suite, pinned so its toolchain cannot drift. The base image is fixed by
# digest, the package archives by a snapshot.debian.org timestamp (every version
# below stays available there), and each tool by exact version.
# Debian Minimal's kernel banner names gcc-14 14.2.0-19 and binutils 2.44, which
# only this pinned toolchain writes (see adapter.conf KERNEL_BANNER).
#
# The app and scripts/build-base.py tag the image
# antinomie-builder:<first 12 hex digits of this file's SHA-256>, so a changed
# pin builds a new image and the old one stays until it is removed.
FROM debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    stamp=20261020T213255Z; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n' "$stamp" "$stamp" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/80antinomie-snapshot; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bc=1.07.1-4 \
        binutils=2.44-3 \
        bison=2:3.8.2+dfsg-1+b2 \
        busybox-static=1:1.37.0-6+b9 \
        ca-certificates=20250419+deb13u1 \
        ccache=4.11.2-2 \
        cpio=2.15+dfsg-2 \
        curl=8.14.1-2+deb13u7 \
        dpkg-dev=1.22.22 \
        dwarves=1.30-1 \
        e2fsprogs=1.47.2-3+b12 \
        fdisk=2.41.5-0+deb13u1 \
        flex=2.6.4-8.2+b4 \
        gcc=4:14.2.0-1 \
        gcc-14=14.2.0-19 \
        kmod=34.2-2 \
        libarchive13t64=3.7.4-4+deb13u1 \
        libelf-dev=0.192-4 \
        libssl-dev=3.5.7-1~deb13u3 \
        make=4.4.1-2 \
        mmdebstrap=1.5.7-1+deb13u1 \
        openssl=3.5.7-1~deb13u3 \
        patch=2.8-2 \
        perl=5.40.1-6+deb13u1 \
        python3=3.13.5-1 \
        qemu-utils=1:10.0.13+ds-0+deb13u1 \
        quilt=0.68-1 \
        uidmap=1:4.17.4-2 \
        xz-utils=5.8.1-1+deb13u2 \
        zstd=1.5.7+dfsg-1 ; \
    rm -rf /var/lib/apt/lists/*
LABEL org.antinomie.builder="1"
WORKDIR /
