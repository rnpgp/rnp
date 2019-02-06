export PATH=/usr/local/bin:$PATH
export MAKE=gmake

: "${CORES:=$(sysctl -n hw.ncpu)}"
export CORES

