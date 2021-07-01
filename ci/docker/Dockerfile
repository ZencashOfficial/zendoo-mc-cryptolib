ARG FROM_IMAGE=zencash/sc-ci-base:focal_rust-stable_latest

FROM $FROM_IMAGE

RUN set -euxo pipefail \
    && apt-get update \
    && [ "$(grep DISTRIB_CODENAME /etc/lsb-release | cut -d= -f2)" = "bionic" ] \
    && python_pkgname="python-minimal" \
    || python_pkgname="python2-minimal" \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $python_pkgname \
    && apt-get -y clean \
    && apt-get -y autoclean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /tmp/*
