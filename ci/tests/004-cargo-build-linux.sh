#!/bin/bash

set -xeo pipefail

cargo $CARGOARGS build --release --all-features
