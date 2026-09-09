#!/bin/bash

set -euxo pipefail

# Wintun ships as a signed DLL that tincd loads at runtime. Fetch the latest
# release and extract the 64-bit DLL so the installer can bundle it next to
# tincd.exe. Unlike the old TAP-Windows driver there is no separate driver
# installer: tincd creates the adapter on demand via the DLL API, which is why
# the installer no longer runs a tap-windows setup executable.
curl -o wintun.zip -L 'https://www.wintun.net/builds/wintun-0.14.1.zip'
unzip -o -j wintun.zip 'wintun/bin/amd64/wintun.dll' -d .ci/package/win/
rm -f wintun.zip

makensis .ci/package/win/installer.nsi
