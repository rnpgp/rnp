export PATH=/usr/local/bin:$PATH
brew_prefix=$(brew --prefix)
: "${CXXFLAGS:=}"
: "${LDFLAGS:=}"
export CXXFLAGS="${CXXFLAGS} -I${brew_prefix}/include"
export LDFLAGS="$LDFLAGS -L${brew_prefix}/lib"

: "${CORES:=$(sysctl -n hw.ncpu)}"
export CORES

export MAKE=make

