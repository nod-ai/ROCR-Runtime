#!/bin/bash

set -euo pipefail

for i in {1..20}; do
  echo clear > /sys/kernel/debug/kmemleak
done

exe=$1
shift 1

for i in {1..100}; do
  $exe $@ > /dev/null
  break
done

sleep 30

for i in {1..10}; do
  echo scan > /sys/kernel/debug/kmemleak
  cat /sys/kernel/debug/kmemleak
#  leak=$(echo scan > /sys/kernel/debug/kmemleak && head -n100 /sys/kernel/debug/kmemleak | grep -A18 aie_hsa_test)
#  if [[ $leak != "" ]]; then
#      echo "leak detected!!!"
#      echo "$leak"
#      exit -1
#  fi
  break
done