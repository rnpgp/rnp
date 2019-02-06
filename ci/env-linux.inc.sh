: "${CORES:=$(grep -c '^$' /proc/cpuinfo)}"
export CORES
export MAKE=make

