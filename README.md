Prerequisites
===========
CentOS7

```
yum install -y automake gcc make openssl-devel bzip2-devel libtool
```

Compile
=========

(Prefix /usr/local by default)
```
autoreconf -ivf
pushd src/libtransit
./configure --mandir=/usr/share/man
popd
pushd src/netpgpverify
./configure --mandir=/usr/share/man
popd
./configure 
make
make install
```

Running commands
=====

```
netpgpkeys
```

