#!/bin/bash
set -eu

if [ "$BUILD_MODE" = "coverage" ]; then
  bash <(curl -s https://codecov.io/bash)
fi

