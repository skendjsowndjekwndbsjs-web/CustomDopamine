#!/bin/sh
# Run this on a machine with normal internet access (your Arch box is fine).
# This sandbox's network allowlist doesn't include apt.procurs.us, so this
# step has to happen on your end, once. After this, the file lives inside
# the repo/IPA and nothing fetches it again at install or run time.
set -e

URL="https://apt.procurs.us/bootstraps/1800/bootstrap-ssh-iphoneos-arm64.tar.zst"
DEST="Application/Dopamine/bootstrap_1800.tar.zst"

echo "Fetching $URL"
curl -fL "$URL" -o "$DEST"
echo "Saved to $DEST"
echo
echo "Sanity check (should print a zstd-compressed data message):"
file "$DEST"
echo
echo "If that URL 404s (Procursus sometimes reshuffles version buckets),"
echo "browse https://apt.procurs.us/bootstraps/ and use whatever directory"
echo "corresponds to iOS 15.x, then re-run with that number instead of 1800."
