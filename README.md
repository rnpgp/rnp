Prerequisites
=============

Start container:
```
docker run -it centos:7 -v ~/src/netpgp:/usr/local/netpgp bash
```

```
yum install -y automake gcc make openssl-devel bzip2-devel libtool rpmdevtools rpm-build chrpath
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
rpmdev-setuptree
```

Run the rpmbuild script.
```
version=1
cd /usr/local/
netpgp/packaging/redhat/extra/package-builder.sh $version
```

