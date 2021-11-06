#!/usr/bin/env bash

: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"
export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"
export CC=${CC-gcc} 
export CXX=${CXX-g++}
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
