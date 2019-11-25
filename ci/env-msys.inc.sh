: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"
export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"
export CC=gcc
export CXX=g++
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
