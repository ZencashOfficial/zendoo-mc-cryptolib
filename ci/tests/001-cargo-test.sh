#!/bin/bash

set -xeo pipefail

# shellcheck disable=SC2086
cargo $CARGOARGS test --all-features
