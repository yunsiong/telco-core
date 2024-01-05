#!/usr/bin/env bash

helper_modern=$1
helper_legacy=$2
output_dir=$3
host_os=$4
resource_compiler=$5
resource_config=$6
lipo=$7

priv_dir="$output_dir/telco-helper@emb"

mkdir -p "$priv_dir"

case $host_os in
  macos|ios|watchos|tvos)
    embedded_helper="$priv_dir/telco-helper"

    if [ -f "$helper_modern" -a -f "$helper_legacy" ]; then
      "$lipo" "$helper_modern" "$helper_legacy" -create -output "$embedded_helper" || exit 1
    elif [ -f "$helper_modern" ]; then
      cp "$helper_modern" "$embedded_helper" || exit 1
    elif [ -f "$helper_legacy" ]; then
      cp "$helper_legacy" "$embedded_helper" || exit 1
    else
      echo "At least one helper must be provided"
      exit 1
    fi

    exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/telco-data-helper-process" "$embedded_helper"
    ;;
  *)
    if [ $host_os = windows ]; then
      exe_suffix=".exe"
    else
      exe_suffix=""
    fi

    embedded_helper_modern="$priv_dir/telco-helper-64$exe_suffix"
    embedded_helper_legacy="$priv_dir/telco-helper-32$exe_suffix"

    if [ -f "$helper_modern" ]; then
      cp "$helper_modern" "$embedded_helper_modern" || exit 1
    else
      touch "$embedded_helper_modern"
    fi

    if [ -f "$helper_legacy" ]; then
      cp "$helper_legacy" "$embedded_helper_legacy" || exit 1
    else
      touch "$embedded_helper_legacy"
    fi

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/telco-data-helper-process" "$embedded_helper_modern" "$embedded_helper_legacy"
    ;;
esac
