#!/bin/bash
docker run -ti -v $(pwd):/usr/local/rnp --rm travisci/ci-garnet:packer-1490989530 bash -l

