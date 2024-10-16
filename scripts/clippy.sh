#!/bin/sh

set -x
cargo clippy --all-features --all-targets -- -Dclippy::all -Dwarnings "$@"
