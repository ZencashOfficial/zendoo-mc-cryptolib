#!/bin/bash

# store original shell options
OLDOPTS="$(set +o); set -${-//c}"
set -euo pipefail

command -v docker &> /dev/null && have_docker="true" || have_docker="false"
# absolute path to project from relative location of this script
workdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
# defaults if not provided via env
DOCKER_ORG="${DOCKER_ORG:-zencash}"
IMAGE_NAME="${IMAGE_NAME:-sc-ci-base}"
IMAGE_TAG="${IMAGE_TAG:-bionic_rust-stable_latest}"
FROM_IMAGE="${DOCKER_ORG}/${IMAGE_NAME}:${IMAGE_TAG}"
NEW_IMAGE_NAME="zendoo-mc-cryptolib-ci"
NEW_FROM_IMAGE="${DOCKER_ORG}/${NEW_IMAGE_NAME}:${IMAGE_TAG}"

# build image with python2 installed from base image
if [ -n "${TESTS:-}" ]; then
  if [ "$have_docker" = "true" ]; then
    docker build --build-arg FROM_IMAGE="$FROM_IMAGE" -t "$NEW_FROM_IMAGE" "$workdir"/ci/docker
    export IMAGE_NAME="$NEW_IMAGE_NAME"
    export FROM_IMAGE="$NEW_FROM_IMAGE"
  fi
else
  echo "No TESTS defined, nothing to do."
  exit 1
fi

# restore original shell options
set +vx; eval "${OLDOPTS}"
