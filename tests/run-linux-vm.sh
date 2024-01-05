#!/bin/sh

if [ -z "$1" ]; then
  echo "Usage: $0 <arch>" > /dev/stderr
  exit 1
fi
arch=$1
shift 1

case $arch in
  mips)
    vm=mips32
    ;;
  mipsel)
    vm=mips32el
    ;;
  *)
    echo "Unsupported architecture: $arch" > /dev/stderr
    exit 1
esac

srcdir=$(cd $(dirname "$0") && pwd)
builddir=$(cd ../build/tmp_thin-linux-$arch/telco-core && pwd)
intdir=$(mktemp -d)

cleanup() {
  rm -rf "$intdir"
}
trap cleanup EXIT

echo "Using: $intdir"
set -e

. ../build/telco-env-linux-$arch.rc
ninja -C $builddir
cd $builddir/tests
cp -a telco-tests labrats "$intdir/"
cd "$intdir"
arm_now install $vm
arm_now resize 500M
"$srcdir/vm.py" $vm "$@"
