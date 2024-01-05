#!/bin/sh

arch=arm64

remote_prefix=/data/local/tmp/telco-tests-$arch

core_tests=$(dirname "$0")
cd "$core_tests/../../build/tmp-android-$arch/telco-core" || exit 1
. ../../telco-env-macos-x86_64.rc
ninja || exit 1
cd tests
adb shell "mkdir $remote_prefix"
adb push telco-tests labrats ../lib/agent/telco-agent.so $remote_prefix || exit 1
adb shell "su -c '$remote_prefix/telco-tests $@'"
