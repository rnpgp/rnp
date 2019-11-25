: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"
export CFLAGS="${CFLAGS} -fstack-protector -fopenmp"
export CXXFLAGS="${CXXFLAGS} -fstack-protector -fopenmp"
export LDFLAGS="${LDFLAGS} -fstack-protector -fopenmp"
export CC=gcc
export CXX=g++
: "${CORES:=$(nproc --all)}"
export CORES
export MAKE=make
