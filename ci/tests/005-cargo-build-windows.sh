#!/bin/bash

set -xeo pipefail

cargo $CARGOARGS build --target=x86_64-pc-windows-gnu --release --all-features
