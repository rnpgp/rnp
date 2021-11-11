#!/usr/bin/env bash

# We rely on CC and CXX set either to gcc/g++ or to clang/clang++ 
# by calling GHA workflow

: "${PATH:=}"
: "${LD_LIBRARY_PATH:=}"
: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"

if [[ "${CC}" = "clang" ]]; then
# clang paths shall have higher priority
  PATH="/clang64/bin:${PATH}"
  LD_LIBRARY_PATH="/clang64/bin:${LD_LIBRARY_PATH}"

  CFLAGS="-I/clang64/include ${CFLAGS}"
  CXXFLAGS="-I/clang64/include ${CXXFLAGS}"
  LDFLAGS="-L/clang64/lib ${LDFLAGS} -lomp"
fi
# -isystem=/clang64/include  
export PATH="${PATH}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}"
export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
