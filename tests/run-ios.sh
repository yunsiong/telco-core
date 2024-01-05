#!/bin/sh

arch=arm64e

remote_host=iphone
remote_prefix=/usr/local/opt/telco-tests-$arch

core_tests=$(cd $(dirname "$0") && pwd)

make -C .. build/.core-ios-stamp-telco-ios-$arch

cd "$core_tests/../../build/tmp-ios-$arch/telco-core" || exit 1

. ../../telco-env-macos-x86_64.rc
ninja || exit 1

cd tests

ssh "$remote_host" "mkdir -p '$remote_prefix'"
rsync -rLz \
  telco-tests \
  labrats \
  ../lib/agent/telco-agent.dylib \
  ../../../telco-ios-arm64e/lib/telco-gadget.dylib \
  "$core_tests/test-gadget-standalone.js" \
  "$remote_host:$remote_prefix/" || exit 1

ssh "$remote_host" "$remote_prefix/telco-tests" "$@"
