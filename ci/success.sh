#!/bin/bash
set -eu

if [ "$BUILD_MODE" = "coverage" ]; then
  cd src/tests
  gcov-4.8 --object-file rnp_tests-rnp_tests.o rnp_tests.c
  bash <(curl -s https://codecov.io/bash)
fi

