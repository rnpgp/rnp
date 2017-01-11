Prerequisites
=============

CentOS7

```
yum install -y automake gcc make openssl-devel bzip2-devel libtool
```

Compile
=======

(Prefix /usr/local by default)
```
autoreconf -ivf
pushd src/netpgpverify
./configure --mandir=/usr/share/man
popd
./configure
make
make install
```

Running commands
================

```
netpgp
netpgpkeys
netpgpverify
```

Building RPM
============

Set up build environment.
```
yum install -y rpmdevtools rpm-build chrpath
rpmdev-setuptree
```

Run the rpmbuild script.
```
version=1
netpgp/packaging/redhat/extra/package-builder.sh $version
```

