#!/usr/bin/env bash
set -eux

. ci/env-windows.inc.sh

: "${CTEST_PARALLEL:=$CORES}"

#  use test costs to prioritize
mkdir -p "build/Testing/Temporary"
cp "cmake/CTestCostData.txt" "build/Testing/Temporary"

cd build
ctest -j"${CTEST_PARALLEL}" -V -R -C Debug cli_tests.*
cd ..

exit 0
