#!/bin/sh
# Minimal `xcrun` shim for Linux.
#
# BaseBin's Makefiles are written the way Apple's own Xcode/macOS CI expects
# (they call `xcrun --sdk iphoneos --show-sdk-path` directly), but `xcrun`
# is a macOS-only tool and does not exist on Linux at all. This script
# fakes just enough of it for those Makefiles to work against your
# existing Theos SDK.
#
# Install:
#   sudo install -m755 xcrun.sh /usr/local/bin/xcrun
#
# Uses $THEOS (already set on this machine to /home/koutouboss/theos) and
# picks the iOS 15.x SDK specifically, since that's this project's target.

THEOS="${THEOS:-$HOME/theos}"
SDK="$THEOS/sdks/iPhoneOS15.6.sdk"

case "$1 $2" in
  "--sdk iphoneos")
    if [ "$3" = "--show-sdk-path" ]; then
      if [ ! -d "$SDK" ]; then
        echo "xcrun shim: SDK not found at $SDK" >&2
        exit 1
      fi
      echo "$SDK"
      exit 0
    fi
    ;;
esac

echo "xcrun shim: unhandled invocation: xcrun $*" >&2
exit 1
