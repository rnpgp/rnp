#!/bin/bash

[ $# -eq 0 ] && CMD='bash -l' || CMD=$*

docker run \
  --tty \
  --interactive \
  --cap-add SYS_PTRACE \
  --volume "$(pwd):/usr/local/rnp" \
  --workdir /usr/local/rnp \
  --user 2000 \
  --rm \
  travisci/ci-garnet:packer-1512502276-986baf0 \
  $CMD

