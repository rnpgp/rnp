#!/usr/bin/env bash

# We rely on CC and CXX set either to gcc/g++ or to clang/clang++ 
# by calling GHA workflow

: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"

if [[ "${CC}" = "clang" ]]; then
# clang paths shall have higher priority
  LDFLAGS="-L/clang64/lib ${LDFLAGS}"
  CFLAGS="-I/clang64/include ${CFLAGS}"
  CXXFLAGS="-isystem=/clang64/include -I/clang64/include ${CXXFLAGS}"
fi

export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
