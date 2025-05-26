#!/usr/bin/env bash
#
# Update the minimal/recent lock file
set -euo pipefail

if [[ "$(uname)" == "Darwin" ]]; then
    CP="cp -f"
else
    CP="cp --force"
fi

for file in Cargo-minimal.lock Cargo-recent.lock; do
    $CP "$file" Cargo.lock
    cargo check
    $CP Cargo.lock "$file"
done
