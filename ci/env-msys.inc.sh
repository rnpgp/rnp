#!/usr/bin/env bash

# We rely on CC and CXX set either to gcc/g++ or to clang/clang++ 
# by calling GHA workflow

: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"
export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
