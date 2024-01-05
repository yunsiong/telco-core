#!/bin/sh

arch=x86_64

telco_tests=$(dirname "$0")
cd "$telco_tests/../../build/tmp_thin-linux-$arch/telco-core" || exit 1
. ../../telco_thin-env-linux-x86_64.rc
ninja || exit 1
tests/telco-tests "$@"
