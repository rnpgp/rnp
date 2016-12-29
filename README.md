Compile
=========

```
autoreconf -ivf
pushd src/libtransit
./configure
popd
./configure
make
make install
```

Running commands
=====

```
export LD_LIBRARY_PATH=/usr/lib
```

